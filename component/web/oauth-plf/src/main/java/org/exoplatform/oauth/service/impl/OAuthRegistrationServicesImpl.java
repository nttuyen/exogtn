/*
 * Copyright (C) 2012 eXo Platform SAS.
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
import org.exoplatform.container.xml.ValueParam;
import org.exoplatform.oauth.service.OAuthAccountGenerator;
import org.exoplatform.oauth.service.OAuthRegistrationServices;
import org.exoplatform.oauth.service.OAuthUserDetector;
import org.exoplatform.services.organization.User;
import org.gatein.security.oauth.spi.AccessTokenContext;
import org.gatein.security.oauth.spi.OAuthPrincipal;
import org.gatein.security.oauth.spi.OAuthProviderType;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class OAuthRegistrationServicesImpl implements OAuthRegistrationServices {
    private final List<String> registerOnFly;

    private final OAuthUserDetector userDetector;
    private final OAuthAccountGenerator accountGenerator;

    public OAuthRegistrationServicesImpl(InitParams initParams, OAuthUserDetector userDetector, OAuthAccountGenerator accountGenerator) {
        ValueParam onFly = initParams.getValueParam("registerOnFly");
        String onFlyValue = onFly == null ? "" : onFly.getValue();
        if(onFlyValue != null && !onFlyValue.isEmpty()) {
            registerOnFly = Arrays.asList(onFlyValue.split(","));
        } else {
            registerOnFly = Collections.EMPTY_LIST;
        }

        this.userDetector = userDetector;
        this.accountGenerator = accountGenerator;
    }

    @Override
    public boolean isRegistrationOnFly(OAuthProviderType<? extends AccessTokenContext> oauthProviderType) {
        return registerOnFly.contains(oauthProviderType.getKey());
    }

    @Override
    public User detectGateInUser(HttpServletRequest request, OAuthPrincipal<? extends AccessTokenContext> principal) {
        return userDetector.detectGateInUser(request, principal);
    }

    @Override
    public User createGateInUser(OAuthPrincipal<? extends AccessTokenContext> principal) {
        return accountGenerator.createGateInUser(principal);
    }
}
