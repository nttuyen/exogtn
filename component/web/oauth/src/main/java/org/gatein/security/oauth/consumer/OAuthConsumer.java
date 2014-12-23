package org.gatein.security.oauth.consumer;

import java.util.Properties;

/**
 * Created by tuyennt on 12/3/14.
 */
public class OAuthConsumer {
    public final String name;
    public final String apiKey;
    public final String apiSecret;
    public final String scope;
    public final OAuthProvider provider;

    //TODO: this properties is need any more?
    public final Properties properties;

    public OAuthConsumer(String name, String apiKey, String apiSecret, String scope, OAuthProvider provider, Properties properties) {
        this.name = name;
        this.apiKey = apiKey;
        this.apiSecret = apiSecret;
        this.scope = scope;
        this.provider = provider;
        this.properties = properties;
    }

    public boolean isOAuth2() {
        return "2.0".equals(provider.getVersion());
    }
}
