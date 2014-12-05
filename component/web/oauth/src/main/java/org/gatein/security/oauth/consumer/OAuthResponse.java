package org.gatein.security.oauth.consumer;

import org.scribe.model.Response;

import java.io.InputStream;
import java.util.Map;

/**
 * Created by tuyennt on 12/3/14.
 */
public class OAuthResponse {
    private final Response response;
    public OAuthResponse(Response response) {
        this.response = response;
    }

    public boolean isSuccessful() {
        return response.isSuccessful();
    }

    public String getHeader(String name) {
        return response.getHeader(name);
    }

    public String getBody() {
        return response.getBody();
    }

    public Map<String, String> getHeaders() {
        return response.getHeaders();
    }

    public String getMessage() {
        return response.getMessage();
    }

    public int getCode() {
        return response.getCode();
    }

    public InputStream getStream() {
        return response.getStream();
    }
}
