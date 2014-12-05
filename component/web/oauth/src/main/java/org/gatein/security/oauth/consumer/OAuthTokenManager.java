package org.gatein.security.oauth.consumer;

/**
 * Created by tuyennt on 12/3/14.
 */
public interface OAuthTokenManager {
    Token getAccessToken(OAuthConsumer consumer);
    void saveAccessToken(OAuthConsumer consumer, Token token);
    Token cleanAccessToken(OAuthConsumer consumer);
}
