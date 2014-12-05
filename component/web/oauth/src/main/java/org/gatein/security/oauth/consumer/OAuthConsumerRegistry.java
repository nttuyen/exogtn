package org.gatein.security.oauth.consumer;

/**
 * Created by tuyennt on 12/3/14.
 */
public interface OAuthConsumerRegistry {
    public OAuthConsumer getConsumer(String name);
}
