package org.gatein.security.oauth.web.generic;

import org.gatein.security.oauth.consumer.*;
import org.gatein.security.oauth.consumer.exception.OAuthRedirectException;
import org.gatein.security.oauth.consumer.impl.OAuthServiceImpl;
import org.gatein.security.oauth.consumer.impl.SessionOAuthTokenManager;
import org.gatein.sso.agent.filter.api.AbstractSSOInterceptor;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * Created by tuyennt on 12/4/14.
 */
public class TwitterAppFilter extends AbstractSSOInterceptor {
    private OAuthConsumerRegistry oAuthConsumerRegistry;
    @Override
    protected void initImpl() {
        oAuthConsumerRegistry = (OAuthConsumerRegistry)getExoContainer().getComponentInstanceOfType(OAuthConsumerRegistry.class);
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        String protectedResourceURL = "https://api.twitter.com/1.1/account/verify_credentials.json";
        String linkedInResourceURL = "https://api.linkedin.com/v1/people/~:(id,first-name,last-name,email-address,public-profile-url,picture-url)?format=json";
        String param = servletRequest.getParameter("load");

        HttpServletRequest request = (HttpServletRequest)servletRequest;
        HttpServletResponse response = (HttpServletResponse)servletResponse;
        PrintWriter out = response.getWriter();
        writeHeader(out);

        String url = request.getRequestURI() + "?load=twitter";
        String linkedInURL = request.getRequestURI() + "?load=linkedin";
        if(param == null) {
            out.println("<a href=\"" + url + "\">Load twitter data</a>");
            out.println("<a href=\"" + linkedInURL + "\">Load LinkedIn data</a>");
            writeFooter(out);
            return;
        }

        String consumerName = param;
        OAuthService oAuthService = (OAuthService)getContainer().getComponentInstanceOfType(OAuthService.class);
        OAuthConsumer consumer = oAuthConsumerRegistry.getConsumer(consumerName);
        OAuthTokenManager tokenManager = new SessionOAuthTokenManager(request);
        OAuthAccessor accessor = oAuthService.getAccessor(consumer, tokenManager);
        String resource = "twitter".equals(consumerName) ? protectedResourceURL : linkedInResourceURL;
        try {
            OAuthResponse oauthRes = accessor.getProtectedResource("GET", resource);
            out.println(oauthRes.getBody());
        } catch (Exception ex) {
            if(ex instanceof OAuthRedirectException) {
                OAuthRedirectException re = (OAuthRedirectException)ex;
                response.sendRedirect(re.redirectURL);
                return;
            }
            ex.printStackTrace(out);
        }

        writeFooter(out);
    }

    private void writeHeader(PrintWriter out) {
        out.println("<html>");
        out.println("<head>");
        out.println("<title>calendar test</title>");
        out.println("</head>");
        out.println("<body>");
    }
    private void writeFooter(PrintWriter out) {
        out.println("</body>");
        out.println("</html>");
    }

    @Override
    public void destroy() {

    }
}
