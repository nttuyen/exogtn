package org.gatein.security.oauth.consumer.impl;
import org.gatein.security.oauth.consumer.OAuthConsumer;
import org.gatein.security.oauth.consumer.OAuthTokenManager;
import org.gatein.security.oauth.consumer.Token;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * Created by tuyennt on 12/4/14.
 */
public class SessionOAuthTokenManager implements OAuthTokenManager {
    private final HttpServletRequest request;

    public SessionOAuthTokenManager(HttpServletRequest request) {
        this.request = request;
    }

    @Override
    public Token getAccessToken(OAuthConsumer consumer) {
        HttpSession session = this.request.getSession();
        Token accessToken = (Token)session.getAttribute(getSessionKeyOfAccessToken(consumer));
        return accessToken;
    }

    @Override
    public void saveAccessToken(OAuthConsumer consumer, Token accessToken) {
        HttpSession session = this.request.getSession();
        session.setAttribute(getSessionKeyOfAccessToken(consumer), accessToken);
    }

    @Override
    public Token cleanAccessToken(OAuthConsumer consumer) {
        HttpSession session = this.request.getSession();
        String key = getSessionKeyOfAccessToken(consumer);
        Token accessToken = (Token)session.getAttribute(key);
        if(accessToken != null) {
            session.setAttribute(key, null);
        }
        return accessToken;
    }

    private String getSessionKeyOfAccessToken(OAuthConsumer consumer) {
        return "oauth." + consumer.name + ".accessToken";
    }
}
