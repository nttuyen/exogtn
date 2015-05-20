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

import org.exoplatform.container.xml.InitParams;
import org.exoplatform.oauth.service.OAuthAccountGenerator;
import org.exoplatform.services.organization.OrganizationService;
import org.exoplatform.services.organization.User;
import org.exoplatform.services.organization.UserProfile;
import org.exoplatform.services.organization.UserProfileHandler;
import org.exoplatform.services.organization.impl.UserImpl;
import org.gatein.common.logging.Logger;
import org.gatein.common.logging.LoggerFactory;
import org.gatein.security.oauth.common.OAuthConstants;
import org.gatein.security.oauth.spi.AccessTokenContext;
import org.gatein.security.oauth.spi.OAuthPrincipal;
import org.gatein.security.oauth.spi.OAuthProviderType;

/**
 * @author <a href="mailto:tuyennt@exoplatform.com">Tuyen Nguyen The</a>.
 */
public class OAuthAccountGeneratorImpl implements OAuthAccountGenerator {
    private static Logger log = LoggerFactory.getLogger(OAuthAccountGeneratorImpl.class);

    private final OrganizationService orgService;

    public OAuthAccountGeneratorImpl(InitParams initParams, OrganizationService orgService) {
        this.orgService = orgService;
    }

    @Override
    public User createGateInUser(OAuthPrincipal<? extends AccessTokenContext> principal) {
        OAuthProviderType providerType = principal.getOauthProviderType();

        String email = principal.getEmail();
        String username = principal.getUserName();
        if(OAuthConstants.OAUTH_PROVIDER_KEY_LINKEDIN.equalsIgnoreCase(providerType.getKey())) {
            username = email.substring(0, email.indexOf('@'));
        }

        User user = new UserImpl(username);
        user.setFirstName(principal.getFirstName());
        user.setLastName(principal.getLastName());
        user.setEmail(email);
        user.setDisplayName(principal.getDisplayName());

        try {
            orgService.getUserHandler().createUser(user, true);

            //User profile
            UserProfileHandler profileHandler = orgService.getUserProfileHandler();

            UserProfile newUserProfile = profileHandler.findUserProfileByName(user.getUserName());
            if (newUserProfile == null) {
                newUserProfile = orgService.getUserProfileHandler().createUserProfileInstance(user.getUserName());
            }

            newUserProfile.setAttribute(providerType.getUserNameAttrName(), principal.getUserName());
            profileHandler.saveUserProfile(newUserProfile, true);

        } catch (Exception ex) {
            if (log.isErrorEnabled()) {
                log.error("Exception when trying to create user: " + user + " on-fly");
            }
            user = null;
        }

        return user;
    }
}
