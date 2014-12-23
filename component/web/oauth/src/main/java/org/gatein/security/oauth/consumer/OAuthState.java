package org.gatein.security.oauth.consumer;

/**
 * Created by tuyennt on 12/10/14.
 */
public class OAuthState {
    private OAuthTokenManager tokenManager;
    private Token requestToken;

    public OAuthTokenManager getTokenManager() {
        return tokenManager;
    }

    public void setTokenManager(OAuthTokenManager tokenManager) {
        this.tokenManager = tokenManager;
    }

    public Token getRequestToken() {
        return requestToken;
    }

    public void setRequestToken(Token requestToken) {
        this.requestToken = requestToken;
    }
}
