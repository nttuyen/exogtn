package org.gatein.security.oauth.consumer.exception;

/**
 * Created by tuyennt on 12/4/14.
 */
public class OAuthConsumerNotFoundException extends OAuthException {
    public final String consumerName;

    public OAuthConsumerNotFoundException(String consumerName) {
        this.consumerName = consumerName;
    }

    public OAuthConsumerNotFoundException(String message, String consumerName) {
        super(message);
        this.consumerName = consumerName;
    }

    public OAuthConsumerNotFoundException(String message, Throwable cause, String consumerName) {
        super(message, cause);
        this.consumerName = consumerName;
    }

    public OAuthConsumerNotFoundException(Throwable cause, String consumerName) {
        super(cause);
        this.consumerName = consumerName;
    }

    public OAuthConsumerNotFoundException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace, String consumerName) {
        super(message, cause, enableSuppression, writableStackTrace);
        this.consumerName = consumerName;
    }
}
