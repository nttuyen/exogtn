package org.gatein.security.oauth.consumer;

/**
 * Created by tuyennt on 12/5/14.
 */
public interface OAuthService {
    OAuthAccessor getAccessor(OAuthConsumer consumer, OAuthTokenManager tokenManager);
    String getOAuthEndPoint();
}
