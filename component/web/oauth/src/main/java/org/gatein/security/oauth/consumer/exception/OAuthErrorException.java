package org.gatein.security.oauth.consumer.exception;

/**
 * Created by tuyennt on 12/4/14.
 */
public class OAuthErrorException extends OAuthException {
    public final String errorCode;

    public OAuthErrorException(String errorCode) {
        this.errorCode = errorCode;
    }

    public OAuthErrorException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    public OAuthErrorException(String message, Throwable cause, String errorCode) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public OAuthErrorException(Throwable cause, String errorCode) {
        super(cause);
        this.errorCode = errorCode;
    }

    public OAuthErrorException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace, String errorCode) {
        super(message, cause, enableSuppression, writableStackTrace);
        this.errorCode = errorCode;
    }
}
