package org.gatein.security.oauth.consumer.impl;

import org.gatein.security.oauth.consumer.OAuthProvider;

import java.util.Properties;

/**
 * Created by tuyennt on 12/10/14.
 */
public class OAuthProviderImpl implements OAuthProvider {
    private final String requestTokenEndpoint;
    private final String accessTokenEndpoint;
    private final String authorizationUrl;
    private final String version;
    private final Properties properties;

    public OAuthProviderImpl(String version, String requestTokenEndpoint, String accessTokenEndpoint, String authorizationUrl, Properties properties) {
        this.version = version;
        this.requestTokenEndpoint = requestTokenEndpoint;
        this.accessTokenEndpoint = accessTokenEndpoint;
        this.authorizationUrl = authorizationUrl;
        this.properties = properties;
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
    public String getAuthorizationUrl() {
        return this.authorizationUrl;
    }

    @Override
    public String getVersion() {
        return this.version;
    }

    public String getProperty(String name) {
        if(this.properties != null) {
            return this.properties.getProperty(name);
        }
        return null;
    }
}
