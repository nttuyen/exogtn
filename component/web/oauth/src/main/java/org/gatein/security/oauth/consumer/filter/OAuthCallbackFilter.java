package org.gatein.security.oauth.consumer.filter;

import org.exoplatform.container.PortalContainer;
import org.exoplatform.web.security.AuthenticationRegistry;
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

    public static final String REQUEST_TOKEN_KEY = "requestToken";
    public static final String TOKEN_MANAGER_KEY = "tokenManager";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        OAuthConsumerRegistry consumerRegistry = (OAuthConsumerRegistry)getContainer().getComponentInstanceOfType(OAuthConsumerRegistry.class);
        AuthenticationRegistry authReg = (AuthenticationRegistry)getContainer().getComponentInstanceOfType(AuthenticationRegistry.class);

        HttpServletRequest req = (HttpServletRequest)request;
        HttpServletResponse res = (HttpServletResponse)response;
        HttpSession session = req.getSession();

        String state = req.getParameter("state");
        if(state == null) {
            //. In case of oauth1, we will use requestToken as stateKey
            state = req.getParameter("oauth_token");
        }

        //. Load consumer info
        String consumerName = req.getParameter(PARAM_CONSUMER_NAME);
        OAuthConsumer consumer;
        if(consumerName == null && state != null) {
            consumerName = get(session, state, PARAM_CONSUMER_NAME);
        }
        consumer = consumerRegistry.getConsumer(consumerName);
        if(consumer == null) {
            handleError(state, new OAuthConsumerNotFoundException("Can not find oauth consumer for name: " + consumerName, consumerName), req, res);
            return;
        }

        OAuthService service = build(consumer);
        Token token = null;
        if(state == null) {
            //. How to generate state
            if(consumer.isOAuth2()) {
                state = consumer.name + System.currentTimeMillis();
            } else {
                token = service.getRequestToken();
                state = token.getToken();
            }
        } else {
            token = (Token)authReg.getAttributeOfClient(req, state + "." + REQUEST_TOKEN_KEY);
        }

        OAuthTokenManager tokenManager = (OAuthTokenManager)authReg.getAttributeOfClient(req, state + "." + TOKEN_MANAGER_KEY);
        if(tokenManager == null) {
            tokenManager = new SessionOAuthTokenManager(req);
        }
        if(tokenManager.getAccessToken(consumer) != null) {
            String redirectTo = req.getParameter(PARAM_REDIRECT_TO);

            Utils.cleanAuthenticationRegistry(req, state);
            clearOAuthState(session, state);
            redirect(redirectTo, res);
        }

        String requestTokenKey = state + "." + REQUEST_TOKEN_KEY;
        Object obj = session.getAttribute(requestTokenKey);

        //. Start process OAuth
        String verifierCode;
        if(consumer.isOAuth2()) {
            verifierCode = req.getParameter("code");
        } else {
            verifierCode = req.getParameter("oauth_verifier");
        }
        String error = req.getParameter("error");

        if(obj == null || (verifierCode == null && error == null)) {
            saveOAuthState(consumer, state, req, res);
            session.setAttribute(requestTokenKey, new Integer(0));
            String redirect = service.getAuthorizationUrl(token);
            redirect += "&state="+state;
            res.sendRedirect(redirect);
        } else {
            session.removeAttribute(requestTokenKey);

            if(error != null) {
                handleError(state, new OAuthErrorException("Oauth error with error code is: " + error, error), req, res);
                return;
            }

            Verifier verifier = new Verifier(verifierCode);
            Token accessToken = service.getAccessToken(token, verifier);

            tokenManager.saveAccessToken(consumer, new org.gatein.security.oauth.consumer.Token(accessToken.getToken(), accessToken.getSecret()));

            String redirectTo = req.getParameter(PARAM_REDIRECT_TO);
            if(redirectTo == null) {
                redirectTo = get(session, state, PARAM_REDIRECT_TO);
            }

            Utils.cleanAuthenticationRegistry(req, state);
            clearOAuthState(session, state);
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

    public void saveOAuthState(OAuthConsumer consumer, String state, HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession();
        String redirectTo = request.getParameter(PARAM_REDIRECT_TO);
        if(redirectTo == null) {
            redirectTo = "/";
        }
        String redirectAfterError = request.getParameter(PARAM_REDIRECT_AFTER_ERROR);

        String prefix = state + ".";
        session.setAttribute(prefix + PARAM_CONSUMER_NAME, consumer.name);
        session.setAttribute(prefix + PARAM_REDIRECT_TO, redirectTo);
        session.setAttribute(prefix + PARAM_REDIRECT_AFTER_ERROR, redirectAfterError);
    }

    private void clearOAuthState(HttpSession session, String state) {
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
        String redirectAfterError = get(session, state, PARAM_REDIRECT_AFTER_ERROR);
        clearOAuthState(session, state);
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
