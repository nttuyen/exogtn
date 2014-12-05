package org.gatein.security.oauth.consumer.api;

import org.json.JSONException;
import org.json.JSONObject;
import org.scribe.builder.api.DefaultApi20;
import org.scribe.exceptions.OAuthException;
import org.scribe.extractors.AccessTokenExtractor;
import org.scribe.model.*;
import org.scribe.oauth.OAuth20ServiceImpl;
import org.scribe.oauth.OAuthService;
import org.scribe.utils.OAuthEncoder;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by tuyennt on 12/5/14.
 */
public class OAuth2Api extends DefaultApi20 {
    private final String accessTokenEndpoint;
    private final String authorizationURL;
    private Verb accessTokenVerb = Verb.POST;
    private String accessTokenExtractorPattern = null;


    public OAuth2Api(String accessTokenEndpoint, String authorizationURL) {
        this.accessTokenEndpoint = accessTokenEndpoint;
        this.authorizationURL = authorizationURL;
    }

    @Override
    public String getAccessTokenEndpoint() {
        return this.accessTokenEndpoint;
    }

    public void setAccessTokenVerb(Verb v) {
        this.accessTokenVerb = v;
    }

    public void setAccessTokenPattern(String pattern) {
        this.accessTokenExtractorPattern = pattern;
    }

    @Override
    public Verb getAccessTokenVerb() {
        return Verb.POST;
    }

    @Override
    public String getAuthorizationUrl(OAuthConfig config) {
        StringBuilder url = new StringBuilder(authorizationURL);
        if(authorizationURL.indexOf('?') == -1) {
            url.append("?");
        } else {
            url.append("&");
        }
        url.append("client_id=").append(config.getApiKey())
                .append("&redirect_uri=").append(OAuthEncoder.encode(config.getCallback()))
                .append("&response_type=code");
        if(config.hasScope()) {
            url.append("&scope=").append(OAuthEncoder.encode(config.getScope()));
        }
        return url.toString();
    }

    @Override
    public AccessTokenExtractor getAccessTokenExtractor() {
        return new AccessTokenExtractor() {
            @Override
            public Token extract(String response) {
                String accessToken = "";
                if(accessTokenExtractorPattern != null) {
                    Matcher matcher = Pattern.compile(accessTokenExtractorPattern).matcher(response);
                    if (matcher.find()) {
                        accessToken = OAuthEncoder.decode(matcher.group(1));
                    } else {
                        throw new OAuthException("Response body is incorrect. Can't extract a token from this: '" + response + "'", null);
                    }
                } else {
                    try {
                        JSONObject json = new JSONObject(response);
                        accessToken = json.getString("access_token");
                    } catch (JSONException ex) {
                        ex.printStackTrace();
                    }
                }
                return new Token(accessToken, "", response);
            }
        };
    }

    @Override
    public OAuthService createService(OAuthConfig config) {
        return new OAuth2Service(this, config);
    }

    public class OAuth2Service extends OAuth20ServiceImpl {

        private static final String GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code";
        private static final String GRANT_TYPE = "grant_type";
        private DefaultApi20 api;
        private OAuthConfig config;

        public OAuth2Service(DefaultApi20 api, OAuthConfig config) {
            super(api, config);
            this.api = api;
            this.config = config;
        }

        @Override
        public Token getAccessToken(Token requestToken, Verifier verifier) {
            if(api.getAccessTokenVerb() == Verb.POST) {
                OAuthRequest request = new OAuthRequest(api.getAccessTokenVerb(), api.getAccessTokenEndpoint());
                request.addBodyParameter(OAuthConstants.CLIENT_ID, config.getApiKey());
                request.addBodyParameter(OAuthConstants.CLIENT_SECRET, config.getApiSecret());
                request.addBodyParameter(OAuthConstants.CODE, verifier.getValue());
                request.addBodyParameter(OAuthConstants.REDIRECT_URI, config.getCallback());
                request.addBodyParameter(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
                Response response = request.send();
                return api.getAccessTokenExtractor().extract(response.getBody());
            } else {
                return super.getAccessToken(requestToken, verifier);
            }
        }
    }
}
