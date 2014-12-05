package org.gatein.security.oauth.consumer.exception;

/**
 * Created by tuyennt on 12/4/14.
 */
public class OAuthRedirectException extends OAuthException {
    public final String redirectURL;

    public OAuthRedirectException(String redirectURL) {
        this.redirectURL = redirectURL;
    }

    public OAuthRedirectException(String message, String redirectURL) {
        super(message);
        this.redirectURL = redirectURL;
    }

    public OAuthRedirectException(String message, Throwable cause, String redirectURL) {
        super(message, cause);
        this.redirectURL = redirectURL;
    }

    public OAuthRedirectException(Throwable cause, String redirectURL) {
        super(cause);
        this.redirectURL = redirectURL;
    }

    public OAuthRedirectException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace, String redirectURL) {
        super(message, cause, enableSuppression, writableStackTrace);
        this.redirectURL = redirectURL;
    }
}
