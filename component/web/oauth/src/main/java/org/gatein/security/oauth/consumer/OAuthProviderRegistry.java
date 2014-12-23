package org.gatein.security.oauth.consumer;

/**
 * Created by tuyennt on 12/11/14.
 */
public interface OAuthProviderRegistry {
    OAuthProvider getProvider(String name);
}
