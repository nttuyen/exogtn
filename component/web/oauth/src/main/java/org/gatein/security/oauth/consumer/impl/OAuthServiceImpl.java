package org.gatein.security.oauth.consumer.impl;

import org.exoplatform.container.xml.InitParams;
import org.exoplatform.container.xml.ValueParam;
import org.gatein.security.oauth.consumer.OAuthAccessor;
import org.gatein.security.oauth.consumer.OAuthConsumer;
import org.gatein.security.oauth.consumer.OAuthService;
import org.gatein.security.oauth.consumer.OAuthTokenManager;

/**
 * Created by tuyennt on 12/5/14.
 */
public class OAuthServiceImpl implements OAuthService {
    private final String oauthEndpoint;

    public OAuthServiceImpl(InitParams params) {
        ValueParam endpoint = params.getValueParam("oauthEndpoint");
        if(endpoint != null) {
            this.oauthEndpoint = endpoint.getValue();
        } else {
            this.oauthEndpoint = "http://localhost:8080/portal/oauthEndpoint";
        }
    }

    public String getOAuthEndPoint() {
        return this.oauthEndpoint;
    }

    @Override
    public OAuthAccessor getAccessor(OAuthConsumer consumer, OAuthTokenManager tokenManager) {
        return new OAuthAccessor(consumer, tokenManager, this.oauthEndpoint);
    }
}
