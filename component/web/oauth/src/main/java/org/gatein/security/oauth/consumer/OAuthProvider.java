package org.gatein.security.oauth.consumer;

/**
 * Created by tuyennt on 12/10/14.
 */
public interface OAuthProvider {
    String getVersion();

    String getRequestTokenEndpoint();

    String getAccessTokenEndpoint();

    String getAuthorizationUrl();

    String getProperty(String name);
}
