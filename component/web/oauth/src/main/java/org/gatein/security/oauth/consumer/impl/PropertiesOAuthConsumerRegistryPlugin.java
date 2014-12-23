package org.gatein.security.oauth.consumer.impl;

import org.exoplatform.commons.utils.PrivilegedSystemHelper;
import org.exoplatform.container.xml.InitParams;
import org.exoplatform.container.xml.ValueParam;
import org.gatein.security.oauth.consumer.OAuthConsumer;
import org.gatein.security.oauth.consumer.OAuthProvider;
import org.gatein.security.oauth.consumer.OAuthProviderRegistry;
import org.gatein.security.oauth.consumer.plugin.OAuthConsumerRegistryPlugin;

import java.util.*;

/**
 * Created by tuyennt on 12/11/14.
 */
public class PropertiesOAuthConsumerRegistryPlugin extends OAuthConsumerRegistryPlugin {
    private final String prefix;
    private final OAuthProviderRegistry providerRegistry;

    private Map<String, OAuthConsumer> consumers = null;
    public PropertiesOAuthConsumerRegistryPlugin(InitParams params, OAuthProviderRegistry providerRegistry) {
        this.providerRegistry = providerRegistry;
        ValueParam value = params.getValueParam("keyPrefix");
        if(value != null) {
            this.prefix = value.getValue();
        } else {
            this.prefix = "gatein.oauth.consumer";
        }
    }
    @Override
    public Map<String, OAuthConsumer> getConsumers() {
        if(this.consumers == null) {
            this.consumers = new HashMap<String, OAuthConsumer>();
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
                PropertiesHelper p = new PropertiesHelper(PrivilegedSystemHelper.getProperties(), key);
                String apiKey = p.get("apiKey");
                String apiSecret = p.get("apiSecret");
                String scope = p.get("scope", null);
                String providerName = p.get("provider");
                OAuthProvider provider = providerRegistry.getProvider(providerName);
                if(provider == null) provider = providerRegistry.getProvider(name);
                if(provider != null && apiKey != null && apiSecret != null) {
                    OAuthConsumer consumer = new OAuthConsumer(name, apiKey, apiSecret, scope, provider, p.getProperties());
                    consumers.put(name, consumer);
                }
            }
        }
        return this.consumers;
    }

    public static class PropertiesHelper {
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
