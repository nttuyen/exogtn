package org.gatein.security.oauth.consumer.exception;

/**
 * Created by tuyennt on 12/4/14.
 */
public class OAuthException extends Exception {
    public OAuthException() {
    }

    public OAuthException(String message) {
        super(message);
    }

    public OAuthException(String message, Throwable cause) {
        super(message, cause);
    }

    public OAuthException(Throwable cause) {
        super(cause);
    }

    public OAuthException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
