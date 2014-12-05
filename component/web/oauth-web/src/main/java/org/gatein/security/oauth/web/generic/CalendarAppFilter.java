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
public class CalendarAppFilter extends AbstractSSOInterceptor {
    private OAuthConsumerRegistry oAuthConsumerRegistry;
    @Override
    protected void initImpl() {
        oAuthConsumerRegistry = (OAuthConsumerRegistry)getExoContainer().getComponentInstanceOfType(OAuthConsumerRegistry.class);
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        //String protectedResourceURL = "https://apidata.googleusercontent.com/caldav/v2/exoplatform.com_jsr0l6mqmvcnu127bgke2l3cuo@group.calendar.google.com/events";
        String protectedResourceURL = "https://www.googleapis.com/userinfo/v2/me";
        String param = servletRequest.getParameter("load_calendar");

        HttpServletRequest request = (HttpServletRequest)servletRequest;
        HttpServletResponse response = (HttpServletResponse)servletResponse;
        PrintWriter out = response.getWriter();
        writeHeader(out);

        String url = request.getRequestURI() + "?load_calendar=1";
        if(param == null) {
            out.println("<a href=\"" + url + "\">Load google data</a>");
            writeFooter(out);
            return;
        }

        String consumerName = "google";
        OAuthService oAuthService = (OAuthService)getContainer().getComponentInstanceOfType(OAuthService.class);
        OAuthConsumer consumer = oAuthConsumerRegistry.getConsumer(consumerName);
        OAuthTokenManager tokenManager = new SessionOAuthTokenManager(request);
        OAuthAccessor accessor = oAuthService.getAccessor(consumer, tokenManager);
        try {
            OAuthResponse oauthRes = accessor.getProtectedResource("GET", protectedResourceURL);
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
