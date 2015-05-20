/*
 * Copyright (C) 2015 eXo Platform SAS.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.exoplatform.oauth.filter;

import org.exoplatform.container.PortalContainer;
import org.exoplatform.container.component.RequestLifeCycle;
import org.exoplatform.oauth.service.OAuthRegistrationServices;
import org.exoplatform.services.organization.User;
import org.exoplatform.web.filter.Filter;
import org.exoplatform.web.security.AuthenticationRegistry;
import org.gatein.security.oauth.common.OAuthConstants;
import org.gatein.security.oauth.spi.OAuthPrincipal;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author <a href="mailto:tuyennt@exoplatform.com">Tuyen Nguyen The</a>.
 */
public class OauthSignupOnflyFilter implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        // User already loggedIn
        if (req.getRemoteUser() != null) {
            chain.doFilter(request, response);
            return;
        }

        PortalContainer container = PortalContainer.getCurrentInstance(request.getServletContext());
        AuthenticationRegistry authReg = container.getComponentInstanceOfType(AuthenticationRegistry.class);
        OAuthRegistrationServices regService = container.getComponentInstanceOfType(OAuthRegistrationServices.class);

        User authenticated = (User)authReg.getAttributeOfClient(req, OAuthConstants.ATTRIBUTE_AUTHENTICATED_PORTAL_USER_FOR_JAAS);
        if (authenticated != null) {
            chain.doFilter(request, response);
            return;
        }

        User oauthAuthenticatedUser = (User) authReg.getAttributeOfClient(req, OAuthConstants.ATTRIBUTE_AUTHENTICATED_PORTAL_USER);
        if (oauthAuthenticatedUser == null) {
            // Not in oauth process, do not need to process here
            chain.doFilter(request, response);
            return;
        }

        User detectedUser = (User)authReg.getAttributeOfClient(req, OAuthConstants.ATTRIBUTE_AUTHENTICATED_PORTAL_USER_DETECTED);
        if(detectedUser != null) {
            chain.doFilter(req, res);
            return;
        }

        OAuthPrincipal principal = (OAuthPrincipal) authReg.getAttributeOfClient(req, OAuthConstants.ATTRIBUTE_AUTHENTICATED_OAUTH_PRINCIPAL);
        boolean isOnFly = regService != null && regService.isRegistrationOnFly(principal.getOauthProviderType());
        if (isOnFly) {
            detectedUser = regService.detectGateInUser(req, principal);
            if (detectedUser != null) {
                authReg.setAttributeOfClient(req, OAuthConstants.ATTRIBUTE_AUTHENTICATED_PORTAL_USER_DETECTED, detectedUser);

            } else {
                RequestLifeCycle.begin(container);
                User newUser = regService.createGateInUser(principal);
                RequestLifeCycle.end();

                if (newUser != null) {
                    authReg.removeAttributeOfClient(req, OAuthConstants.ATTRIBUTE_AUTHENTICATED_PORTAL_USER);
                    // send redirect to continue oauth login
                    // TODO: Where should redirect to?
                    res.sendRedirect("/");
                    return;
                }
            }
        }
        chain.doFilter(req, res);
    }
}
