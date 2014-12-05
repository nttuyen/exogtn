package org.gatein.security.oauth.consumer;

import java.io.Serializable;

/**
 * Created by tuyennt on 12/4/14.
 */
public class Token implements Serializable {
    public final String token;
    public final String secret;

    public Token(String token, String secret) {
        this.token = token;
        this.secret = secret;
    }
}
