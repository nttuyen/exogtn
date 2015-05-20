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

package org.exoplatform.oauth.service.impl;

import org.exoplatform.commons.utils.ListAccess;
import org.exoplatform.container.xml.InitParams;
import org.exoplatform.oauth.service.OAuthUserDetector;
import org.exoplatform.services.organization.OrganizationService;
import org.exoplatform.services.organization.Query;
import org.exoplatform.services.organization.User;
import org.exoplatform.services.organization.UserHandler;
import org.exoplatform.services.organization.UserStatus;
import org.gatein.common.logging.Logger;
import org.gatein.common.logging.LoggerFactory;
import org.gatein.security.oauth.common.OAuthConstants;
import org.gatein.security.oauth.spi.AccessTokenContext;
import org.gatein.security.oauth.spi.OAuthPrincipal;
import org.gatein.security.oauth.spi.OAuthProviderType;

import javax.servlet.http.HttpServletRequest;

/**
 * @author <a href="mailto:tuyennt@exoplatform.com">Tuyen Nguyen The</a>.
 */
public class OAuthUserDetectorImpl implements OAuthUserDetector {
    private static Logger log = LoggerFactory.getLogger(OAuthUserDetectorImpl.class);

    private final OrganizationService orgService;

    public OAuthUserDetectorImpl(InitParams initParams, OrganizationService orgService) {
        this.orgService = orgService;
    }

    @Override
    public User detectGateInUser(HttpServletRequest request, OAuthPrincipal<? extends AccessTokenContext> principal) {
        OAuthProviderType providerType = principal.getOauthProviderType();

        String email = principal.getEmail();
        String username = principal.getUserName();
        if(OAuthConstants.OAUTH_PROVIDER_KEY_LINKEDIN.equalsIgnoreCase(providerType.getKey())) {
            username = email.substring(0, email.indexOf('@'));
        }

        User foundUser = null;

        try {
            UserHandler userHandler = orgService.getUserHandler();
            Query query = null;
            ListAccess<User> users = null;

            //Find user by username
            if(username != null) {
                query = new Query();
                query.setUserName(username);
                users = userHandler.findUsersByQuery(query, UserStatus.ANY);
                if(users != null && users.getSize() > 0) {
                    foundUser = users.load(0, 1)[0];
                }
            }

            //Find by email
            if(foundUser == null && email != null) {
                query = new Query();
                query.setEmail(email);
                users = userHandler.findUsersByQuery(query, UserStatus.ANY);
                if(users != null && users.getSize() > 0) {
                    foundUser = users.load(0, 1)[0];
                }
            }

            //TODO: Find by other strategy


        } catch (Exception ex) {
            if (log.isErrorEnabled()) {
                log.error("Exception when trying to detect user: ", ex);
            }
        }


        return foundUser;
    }
}
