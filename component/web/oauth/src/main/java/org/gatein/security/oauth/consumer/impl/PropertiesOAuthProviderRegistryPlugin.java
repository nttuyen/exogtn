package org.gatein.security.oauth.consumer.impl;

import org.exoplatform.commons.utils.PrivilegedSystemHelper;
import org.exoplatform.container.xml.InitParams;
import org.exoplatform.container.xml.ValueParam;
import org.gatein.security.oauth.consumer.OAuthProvider;
import org.gatein.security.oauth.consumer.plugin.OAuthProviderRegistryPlugin;

import java.util.*;

/**
 * Created by tuyennt on 12/11/14.
 */
public class PropertiesOAuthProviderRegistryPlugin extends OAuthProviderRegistryPlugin {
    private final String prefix;
    private Map<String, OAuthProvider> providers = null;
    public PropertiesOAuthProviderRegistryPlugin(InitParams params) {
        ValueParam value = params.getValueParam("keyPrefix");
        if(value != null) {
            prefix = value.getValue();
        } else {
            prefix = "gatein.oauth.provider";
        }
    }

    @Override
    public Map<String, OAuthProvider> getProviders() {
        if(this.providers == null) {
            this.providers = new HashMap<String, OAuthProvider>();
            Properties properties = PrivilegedSystemHelper.getProperties();
            List<String> names = new LinkedList<String>();
            final String keyPrefix = prefix + ".";
            for(String key : properties.stringPropertyNames()) {
                if(key.startsWith(keyPrefix) && key.endsWith(".enable")) {
                    String v = properties.getProperty(key);
                    if("true".equals(v)) {
                        String name = key.replace(keyPrefix, "");
                        name = name.replace(".enable", "");
                        names.add(name);
                    }
                }
            }
            for(String name : names) {
                String key = prefix + "." + name;
                PropertiesHelper p = new PropertiesHelper(properties, key);
                String version = p.get("version", "1.0a");
                String requestTokenEndpoint = p.get("requestTokenEndpoint", null);
                String accessTokenEndpoint = p.get("accessTokenEndpoint", null);
                String authorizationURL = p.get("authorizationURL", null);
                if(authorizationURL != null && accessTokenEndpoint != null) {
                    if("2.0".equals(version) || requestTokenEndpoint != null) {
                        OAuthProvider provider = new OAuthProviderImpl(version, requestTokenEndpoint, accessTokenEndpoint, authorizationURL, p.getProperties());
                        providers.put(name, provider);
                    }
                }
            }
        }
        return this.providers;
    }

    private static class PropertiesHelper {
        private final String prefix;
        private final Properties properties;
        public PropertiesHelper(Properties properties, String prefix) {
            this.properties = properties;
            this.prefix = prefix;
        }
        public String get(String key) {
            String k = prefix + "." + key;
            return properties.getProperty(k);
        }
        public String get(String key, String def) {
            String k = prefix + "." + key;
            try {
                String val = properties.getProperty(k);
                return val != null ? val : def;
            } catch (Exception ex) {
                return def;
            }
        }

        public Properties getProperties() {
            Properties ps = new Properties();
            for(String key : properties.stringPropertyNames()) {
                if(key.startsWith(prefix)) {
                    String value = properties.getProperty(key);
                    ps.put(key, value);
                    ps.put(key.replace(prefix + ".", ""), value);
                }
            }
            return ps;
        }
    }
}
