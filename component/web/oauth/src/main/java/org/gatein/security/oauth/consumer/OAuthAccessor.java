package org.gatein.security.oauth.consumer;

import org.gatein.security.oauth.consumer.exception.OAuthException;
import org.gatein.security.oauth.consumer.exception.OAuthRedirectException;
import org.gatein.security.oauth.consumer.util.Utils;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.oauth.OAuthService;
import org.scribe.utils.OAuthEncoder;

/**
 * Created by tuyennt on 12/4/14.
 */
public class OAuthAccessor {
    private final String oauthEndpoint;
    private final OAuthConsumer consumer;
    private final OAuthService service;
    private final OAuthTokenManager tokenManager;

    private String redirectTo = null;
    private String redirectAfterError = null;

    public OAuthAccessor(OAuthConsumer consumer, OAuthTokenManager tokenManager, String gateinOauthEnpoint) {
        this.consumer = consumer;
        this.tokenManager = tokenManager;
        this.oauthEndpoint = gateinOauthEnpoint;
        String callback = this.getRequestTokenURL();
        service = Utils.buildService(consumer, callback);
    }

    public org.gatein.security.oauth.consumer.Token getAccessToken() {
        return tokenManager.getAccessToken(consumer);
    }

    public OAuthResponse getProtectedResource(String method, String url) throws OAuthException {
        org.gatein.security.oauth.consumer.Token accessToken = tokenManager.getAccessToken(consumer);
        if(accessToken == null) {
            throw new OAuthRedirectException(getRequestTokenURL());
        }
        OAuthRequest request = new OAuthRequest(Verb.valueOf(method.toUpperCase()), url);
        service.signRequest(new Token(accessToken.token, accessToken.secret), request);
        return new OAuthResponse(request.send());
    }

    public String getRequestTokenURL() {
        StringBuilder callback = new StringBuilder(oauthEndpoint);
        callback.append("?consumerName=").append(consumer.name);
        if(this.redirectTo != null) {
            callback.append("&redirectTo=").append(OAuthEncoder.encode(this.redirectTo));
        }
        if(this.redirectAfterError != null) {
            callback.append("&redirectAfterError=").append(OAuthEncoder.encode(this.redirectAfterError));
        }
        return callback.toString();
    }

    public void setRedirectTo(String redirectTo) {
        this.redirectTo = redirectTo;
    }
    public void setRedirectAfterError(String redirectAfterError) {
        this.redirectAfterError = redirectAfterError;
    }
}
