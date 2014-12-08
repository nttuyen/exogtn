package org.exoplatform.oauth.portlet.sample;

import org.gatein.security.oauth.consumer.OAuthConsumer;
import org.gatein.security.oauth.consumer.OAuthTokenManager;
import org.gatein.security.oauth.consumer.Token;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by tuyennt on 12/8/14.
 */
public class SampleOAuthTokenManager implements OAuthTokenManager {
    private static final Map<OAuthConsumer, Token> tokens = new HashMap<OAuthConsumer, Token>();
    public Token getAccessToken(OAuthConsumer consumer) {
        return tokens.get(consumer);
    }

    public void saveAccessToken(OAuthConsumer consumer, Token token) {
        tokens.put(consumer, token);
    }

    public Token cleanAccessToken(OAuthConsumer consumer) {
        return tokens.remove(consumer);
    }
}
