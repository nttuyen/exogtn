package org.gatein.security.oauth.consumer;

import java.util.List;

/**
 * Created by tuyennt on 12/3/14.
 */
public interface OAuthConsumerRegistry {
    public OAuthConsumer getConsumer(String name);
    public List<OAuthConsumer> getConsumers();
}
