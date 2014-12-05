package org.gatein.security.oauth.consumer.api;

import org.scribe.builder.api.DefaultApi10a;
import org.scribe.model.Token;

/**
 * Created by tuyennt on 12/5/14.
 */
public class OAuth1Api extends DefaultApi10a {
    private final String requestTokenEndpoint;
    private final String accessTokenEndpoint;
    private final String authorizationURL;

    public OAuth1Api(String requestTokenEndpoint, String accessTokenEndpoint, String authorizationURL) {
        this.requestTokenEndpoint = requestTokenEndpoint;
        this.accessTokenEndpoint = accessTokenEndpoint;
        this.authorizationURL = authorizationURL;
    }

    @Override
    public String getRequestTokenEndpoint() {
        return this.requestTokenEndpoint;
    }

    @Override
    public String getAccessTokenEndpoint() {
        return this.accessTokenEndpoint;
    }

    @Override
    public String getAuthorizationUrl(Token requestToken) {
        if(authorizationURL.indexOf('?') == -1) {
            return this.authorizationURL + "?oauth_token=" + requestToken.getToken();
        } else {
            return this.authorizationURL + "&oauth_token=" + requestToken.getToken();
        }
    }
}
