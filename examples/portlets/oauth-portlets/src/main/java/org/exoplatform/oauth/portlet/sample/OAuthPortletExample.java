/******************************************************************************
 * JBoss, a division of Red Hat                                               *
 * Copyright 2008, Red Hat Middleware, LLC, and individual                    *
 * contributors as indicated by the @authors tag. See the                     *
 * copyright.txt in the distribution for a full listing of                    *
 * individual contributors.                                                   *
 *                                                                            *
 * This is free software; you can redistribute it and/or modify it            *
 * under the terms of the GNU Lesser General Public License as                *
 * published by the Free Software Foundation; either version 2.1 of           *
 * the License, or (at your option) any later version.                        *
 *                                                                            *
 * This software is distributed in the hope that it will be useful,           *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of             *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU           *
 * Lesser General Public License for more details.                            *
 *                                                                            *
 * You should have received a copy of the GNU Lesser General Public           *
 * License along with this software; if not, write to the Free                *
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA         *
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.                   *
 ******************************************************************************/
package org.exoplatform.oauth.portlet.sample;

import org.exoplatform.container.PortalContainer;
import org.exoplatform.portal.webui.util.Util;
import org.gatein.security.oauth.consumer.*;
import org.gatein.security.oauth.consumer.exception.OAuthException;
import org.gatein.security.oauth.consumer.exception.OAuthRedirectException;
import org.gatein.security.oauth.consumer.impl.SessionOAuthTokenManager;
import org.jgroups.blocks.NotificationBus;

import java.io.IOException;
import java.io.PrintWriter;

import javax.portlet.*;
import javax.servlet.http.HttpServletRequest;


public class OAuthPortletExample extends GenericPortlet {
    private static final String GOOGLE_RESOURCE = "https://www.googleapis.com/userinfo/v2/me";
    private static final String TWITTER_RESOURCE = "https://api.twitter.com/1.1/account/verify_credentials.json";
    private static final String LINKEDIN_RESOURCE = "https://api.linkedin.com/v1/people/~:(id,first-name,last-name,email-address,public-profile-url,picture-url)?format=json";

    public void doView(RenderRequest request, RenderResponse rResponse) throws PortletException, IOException {
        rResponse.setContentType("text/html");
        PrintWriter out = rResponse.getWriter();
        portletHeader(out);

        String load = request.getParameter("load");
        String hasError = request.getParameter("hasError");

        PortletURL googleURL = rResponse.createRenderURL();
        googleURL.setParameter("load", "google");

        PortletURL twitterURL = rResponse.createRenderURL();
        twitterURL.setParameter("load", "twitter");

        PortletURL linkedInURL = rResponse.createRenderURL();
        linkedInURL.setParameter("load", "linkedin");

        out.println("<a href=" + googleURL.toString() + ">Load google data</a><br/>");
        out.println("<a href=" + twitterURL.toString() + ">Load Twiter data</a><br/>");
        out.println("<a href=" + linkedInURL.toString() + ">Load Linkedin data</a><br/>");

        if(load == null) {

        } else {
            String consumerName = load;
            String resourceURL = null;
            if(consumerName.equals("google")) {
                resourceURL = GOOGLE_RESOURCE;
            } else if(consumerName.equals("twitter")) {
                resourceURL = TWITTER_RESOURCE;
            } else if(consumerName.equals("linkedin")) {
                resourceURL = LINKEDIN_RESOURCE;
            }

            HttpServletRequest req = Util.getPortalRequestContext().getRequest();
            out.println("<h3>");
            out.println("Load data from provider: " + consumerName);
            out.println("</h3>");
            out.println("<div> Resource URL: <strong>" + resourceURL + "</strong></div>");
            out.println("<div>");

            PortalContainer container = PortalContainer.getInstance();
            OAuthConsumerRegistry registry = (OAuthConsumerRegistry)container.getComponentInstanceOfType(OAuthConsumerRegistry.class);
            OAuthService oauthService = (OAuthService)container.getComponentInstanceOfType(OAuthService.class);
            OAuthTokenManager tokenManager = new SampleOAuthTokenManager();
            OAuthConsumer consumer = registry.getConsumer(consumerName);
            if(consumer == null) {
                out.println("Can not find oauth consumer for name: " + consumerName);

            } else if(hasError != null) {
                out.println("Has error when trying to get access_token, the exception is:");
                out.println("<br/>");
                OAuthException ex = (OAuthException)req.getSession().getAttribute("OAUTH_EXCEPTION");
                req.getSession().removeAttribute("OAUTH_EXCEPTION");
                if(ex != null) {
                    ex.printStackTrace(out);
                }

            } else {
                OAuthAccessor accessor = oauthService.getAccessor(consumer, tokenManager);
                try {
                    PortletURL redirectTo = rResponse.createRenderURL();
                    redirectTo.setParameter("load", consumerName);
                    accessor.setRedirectTo(redirectTo.toString());

                    PortletURL redirectError = rResponse.createRenderURL();
                    redirectError.setParameter("load", consumerName);
                    redirectError.setParameter("hasError", "1");
                    accessor.setRedirectAfterError(redirectError.toString());

                    accessor.saveOAuthState(req);
                    OAuthResponse resource = accessor.getProtectedResource("GET", resourceURL);
                    accessor.clearOAuthState(req);
                    out.println(resource.getBody());
                } catch (OAuthException ex) {
                    if(ex instanceof OAuthRedirectException) {
                        OAuthRedirectException exc = (OAuthRedirectException)ex;
                        out.println("<div>");
                        out.println("You did not grant access permission for eXo");
                        out.println("<strong><a href=" + exc.redirectURL + ">Please click here to grant permission</a></strong>");
                        out.println("</div>");
                    } else {
                        ex.printStackTrace(out);
                    }
                }
            }
            out.println("</div>");
        }
        portletFooter(out);
    }

    private void portletHeader(PrintWriter out) {
        out.println("<div>");
    }
    private void portletFooter(PrintWriter out) {
        out.println("</div>");
    }
}
