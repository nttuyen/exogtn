package org.gatein.security.oauth.consumer;

import org.exoplatform.container.PortalContainer;
import org.exoplatform.web.security.AuthenticationRegistry;
import org.gatein.security.oauth.consumer.exception.OAuthException;
import org.gatein.security.oauth.consumer.exception.OAuthRedirectException;
import org.gatein.security.oauth.consumer.filter.OAuthCallbackFilter;
import org.gatein.security.oauth.consumer.util.Utils;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.oauth.OAuthService;
import org.scribe.utils.OAuthEncoder;

import javax.servlet.http.HttpServletRequest;

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

    private String state = null;
    private Token requestToken = null;

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
        callback.append("?").append(OAuthCallbackFilter.PARAM_CONSUMER_NAME).append("=").append(consumer.name);
        if(this.redirectTo != null) {
            callback.append("&").append(OAuthCallbackFilter.PARAM_REDIRECT_TO).append("=").append(OAuthEncoder.encode(this.redirectTo));
        }
        if(this.redirectAfterError != null) {
            callback.append("&").append(OAuthCallbackFilter.PARAM_REDIRECT_AFTER_ERROR).append("=").append(OAuthEncoder.encode(this.redirectAfterError));
        }
        if(this.state != null) {
            callback.append("&state=").append(this.state);
        }
        return callback.toString();
    }

    public void setRedirectTo(String redirectTo) {
        this.redirectTo = redirectTo;
    }
    public void setRedirectAfterError(String redirectAfterError) {
        this.redirectAfterError = redirectAfterError;
    }

    public String getOAuthState() {
        if(this.state == null) {
            if(state == null) {
                this.requestToken = getRequestToken();
                if(this.requestToken == null) {
                    state = consumer.name + System.currentTimeMillis();
                } else {
                    state = requestToken.getToken();
                }
            }
        }
        return this.state;
    }
    public void saveOAuthState(HttpServletRequest req) {
        PortalContainer container = PortalContainer.getInstance();
        AuthenticationRegistry authReg = (AuthenticationRegistry)container.getComponentInstanceOfType(AuthenticationRegistry.class);

        String prefix = getOAuthState() + ".";
        authReg.setAttributeOfClient(req, prefix + OAuthCallbackFilter.TOKEN_MANAGER_KEY, this.tokenManager);
        if(this.requestToken != null) {
            authReg.setAttributeOfClient(req, prefix + OAuthCallbackFilter.REQUEST_TOKEN_KEY, this.requestToken);
        }
    }
    public void clearOAuthState(HttpServletRequest req) {
        if(this.state == null) {
            return;
        }
        Utils.cleanAuthenticationRegistry(req, this.state);
        this.state = null;
    }

    private Token getRequestToken() {
        if(consumer.isOAuth2()) {
            return null;
        } else {
            return this.service.getRequestToken();
        }
    }
}
