package org.gatein.security.oauth.consumer.util;

import org.exoplatform.container.PortalContainer;
import org.exoplatform.web.security.AuthenticationRegistry;
import org.gatein.common.classloader.DelegatingClassLoader;
import org.gatein.security.oauth.consumer.OAuthAccessor;
import org.gatein.security.oauth.consumer.OAuthConsumer;
import org.gatein.security.oauth.consumer.api.Google2Api;
import org.gatein.security.oauth.consumer.api.OAuth1Api;
import org.gatein.security.oauth.consumer.api.OAuth2Api;
import org.gatein.security.oauth.consumer.filter.OAuthCallbackFilter;
import org.scribe.builder.ServiceBuilder;
import org.scribe.builder.api.Api;
import org.scribe.model.Verb;
import org.scribe.oauth.OAuthService;

import javax.servlet.http.HttpServletRequest;

/**
 * Created by tuyennt on 12/5/14.
 */
public class Utils {
    public static OAuthService buildService(OAuthConsumer consumer, String callbackURL) {
        Class<? extends Api> api = null;
        Api apiInstance = null;
        try {
            String apiClass = consumer.properties.getProperty("apiClass", null);
            if(apiClass != null) {
                ClassLoader tccl = Thread.currentThread().getContextClassLoader();
                ClassLoader oauth = OAuthAccessor.class.getClassLoader();
                ClassLoader delegating = new DelegatingClassLoader(tccl, oauth);
                api = (Class<? extends Api>) delegating.loadClass(apiClass);
            }
        } catch (Exception ex) {

        } finally {
            if(api == null) {
                String accessTokenEndpoint = consumer.properties.getProperty("accessTokenEndpoint");
                String authorizationURL = consumer.properties.getProperty("authorizationURL");
                String accessTokenMethod = consumer.properties.getProperty("getAccessTokenMethod");
                String accessTokenPattern = consumer.properties.getProperty("accessTokenPattern");
                if(consumer.isOAuth2()) {
                    OAuth2Api instance = new OAuth2Api(accessTokenEndpoint, authorizationURL);
                    if(accessTokenMethod != null && !accessTokenMethod.isEmpty()) {
                        instance.setAccessTokenVerb(Verb.valueOf(accessTokenMethod));
                    }
                    if(accessTokenPattern != null && !accessTokenPattern.isEmpty()) {
                        instance.setAccessTokenPattern(accessTokenPattern);
                    }
                    apiInstance = instance;
                } else {
                    String requestTokenEndpoint = consumer.properties.getProperty("requestTokenEndpoint");
                    apiInstance = new OAuth1Api(requestTokenEndpoint, accessTokenEndpoint, authorizationURL);
                }
            }
        }

        ServiceBuilder builder = new ServiceBuilder()
                .apiKey(consumer.apiKey)
                .apiSecret(consumer.apiSecret)
                .callback(callbackURL);
        if(api != null) {
            builder.provider(api);
        } else {
            builder.provider(apiInstance);
        }
        String scope = consumer.properties.getProperty("scope", null);
        if(scope != null) {
            builder.scope(scope);
        }
        return builder.build();
    }

    public static void cleanAuthenticationRegistry(HttpServletRequest req, String state) {
        PortalContainer container = PortalContainer.getInstance();
        AuthenticationRegistry authReg = (AuthenticationRegistry)container.getComponentInstanceOfType(AuthenticationRegistry.class);

        String prefix = state + ".";
        authReg.removeAttributeOfClient(req, prefix + OAuthCallbackFilter.TOKEN_MANAGER_KEY);
        authReg.removeAttributeOfClient(req, prefix + OAuthCallbackFilter.REQUEST_TOKEN_KEY);
    }
}
