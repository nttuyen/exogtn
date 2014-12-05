package org.gatein.security.oauth.consumer;

import java.util.Properties;

/**
 * Created by tuyennt on 12/3/14.
 */
public class OAuthConsumer {
    public final String name;
    public final String apiKey;
    public final String apiSecret;
    public final Properties properties;

    public OAuthConsumer(String name, String apiKey, String apiSecret, Properties properties) {
        this.name = name;
        this.apiKey = apiKey;
        this.apiSecret = apiSecret;
        this.properties = properties;
    }

    public boolean isOAuth2() {
        String version = properties.getProperty("version", "1.0a");
        return "2.0".equals(version);
    }
}
