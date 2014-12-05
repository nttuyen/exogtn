package org.gatein.security.oauth.consumer.filter;

import org.exoplatform.container.PortalContainer;
import org.gatein.security.oauth.consumer.*;
import org.gatein.security.oauth.consumer.exception.OAuthConsumerNotFoundException;
import org.gatein.security.oauth.consumer.exception.OAuthErrorException;
import org.gatein.security.oauth.consumer.impl.SessionOAuthTokenManager;
import org.gatein.security.oauth.consumer.util.Utils;
import org.scribe.model.Token;
import org.scribe.model.Verifier;
import org.scribe.oauth.OAuthService;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Enumeration;

/**
 * Created by tuyennt on 12/4/14.
 */
public class OAuthCallbackFilter implements org.exoplatform.web.filter.Filter {
    public static final String PARAM_CONSUMER_NAME = "consumerName";
    public static final String PARAM_REDIRECT_TO = "redirectTo";
    public static final String PARAM_REDIRECT_AFTER_ERROR = "redirectAfterError";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        OAuthConsumerRegistry consumerRegistry = (OAuthConsumerRegistry)getContainer().getComponentInstanceOfType(OAuthConsumerRegistry.class);
        HttpServletRequest req = (HttpServletRequest)request;
        HttpServletResponse res = (HttpServletResponse)response;
        HttpSession session = req.getSession();

        String state = req.getParameter("state");
        if(state == null) {
            state = (String)session.getAttribute("OAUTH_STATE");
        }
        String consumerName = req.getParameter(PARAM_CONSUMER_NAME);
        OAuthConsumer consumer;
        if(state == null) {
            consumer = consumerRegistry.getConsumer(consumerName);
            if(consumer == null) {
                handleError(state, new OAuthConsumerNotFoundException("Can not find oauth consumer for name: " + consumerName, consumerName), req, res);
                return;
            } else {
                state = initOAuthState(consumer, req, res);
            }
        } else {
            consumerName = get(session, state, "consumerName");
            consumer = consumerRegistry.getConsumer(consumerName);
            if(consumer == null) {
                handleError(state, new OAuthConsumerNotFoundException("Can not find oauth consumer for name: " + consumerName, consumerName), req, res);
                return;
            }
        }

        String redirectTo = get(session, state, "redirectTo");

        OAuthService service = build(consumer);
        OAuthTokenManager tokenManager = new SessionOAuthTokenManager(req);
        if(tokenManager.getAccessToken(consumer) != null) {
            System.out.println("AccessToken from session: " + tokenManager.getAccessToken(consumer));
            clearState(session, state);
            redirect(redirectTo, res);
        }

        String requestTokenKey = state + ".requestToken";
        Object obj = session.getAttribute(requestTokenKey);
        Token token = null;

        String verifierCode;
        if(consumer.isOAuth2()) {
            verifierCode = req.getParameter("code");
        } else {
            verifierCode = req.getParameter("oauth_verifier");
        }
        String error = req.getParameter("error");

        if(obj == null || (verifierCode == null && error == null)) {
            if(consumer.isOAuth2()) {
                session.setAttribute(requestTokenKey, new Integer(0));
                token = null;
            } else {
                token = service.getRequestToken();
                session.setAttribute(requestTokenKey, token);
            }
            String redirect = service.getAuthorizationUrl(token);
            redirect += "&state="+state;
            res.sendRedirect(redirect);
        } else {
            if(error != null) {
                handleError(state, new OAuthErrorException("Oauth error with error code is: " + error, error), req, res);
                return;
            }
            session.removeAttribute(requestTokenKey);
            if(!consumer.isOAuth2()) {
                token = (Token)obj;
            }
            Verifier verifier = new Verifier(verifierCode);
            Token accessToken = service.getAccessToken(token, verifier);

            tokenManager.saveAccessToken(consumer, new org.gatein.security.oauth.consumer.Token(accessToken.getToken(), accessToken.getSecret()));

            System.out.println("AccessToken: " + accessToken.getToken());
            clearState(session, state);
            redirect(redirectTo, res);
        }
    }

    private void redirect(String redirectTo, HttpServletResponse res) throws IOException {
        if(redirectTo != null) {
            res.sendRedirect(redirectTo);
        } else {
            res.sendRedirect("/portal");
        }
    }

    private OAuthService build(OAuthConsumer consumer) {
        org.gatein.security.oauth.consumer.OAuthService service =
                (org.gatein.security.oauth.consumer.OAuthService)getContainer().getComponentInstanceOfType(org.gatein.security.oauth.consumer.OAuthService.class);
        return Utils.buildService(consumer, service.getOAuthEndPoint());
    }

    public String initOAuthState(OAuthConsumer consumer, HttpServletRequest request, HttpServletResponse response) {
        String state = consumer.name + System.currentTimeMillis();
        HttpSession session = request.getSession();
        String redirectTo = request.getParameter(PARAM_REDIRECT_TO);
        if(redirectTo == null) {
            redirectTo = "/";
        }
        String redirectAfterError = request.getParameter(PARAM_REDIRECT_AFTER_ERROR);

        session.setAttribute(state + ".consumerName", consumer.name);
        session.setAttribute(state + ".redirectTo", redirectTo);
        session.setAttribute(state + ".redirectAfterError", redirectAfterError);

        if(!consumer.isOAuth2()) {
            session.setAttribute("OAUTH_STATE", state);
        }

        return state;
    }

    private void clearState(HttpSession session, String state) {
        session.removeAttribute("OAUTH_STATE");
        state = state + ".";
        Enumeration<String> keys = session.getAttributeNames();
        while(keys.hasMoreElements()) {
            String key = keys.nextElement();
            if(key.startsWith(state)) {
                session.removeAttribute(key);
            }
        }
    }

    private String get(HttpSession session, String state, String key) {
        return (String)session.getAttribute(state + "." + key);
    }

    private void handleError(String state, Exception ex, HttpServletRequest req, HttpServletResponse res) throws IOException {
        HttpSession session = req.getSession();
        String redirectAfterError = get(session, state, "redirectAfterError");
        clearState(session, state);
        if(redirectAfterError != null) {
            session.setAttribute("OAUTH_EXCEPTION", ex);
            res.sendRedirect(redirectAfterError);
        } else {
            PrintWriter out = res.getWriter();
            ex.printStackTrace(out);
        }
    }

    private PortalContainer getContainer() {
        return PortalContainer.getInstance();
    }
}
