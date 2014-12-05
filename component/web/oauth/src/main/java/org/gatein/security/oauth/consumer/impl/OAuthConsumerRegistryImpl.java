package org.gatein.security.oauth.consumer.impl;

import org.exoplatform.commons.utils.PrivilegedSystemHelper;
import org.exoplatform.container.xml.InitParams;
import org.exoplatform.container.xml.ValueParam;
import org.gatein.security.oauth.consumer.OAuthConsumer;
import org.gatein.security.oauth.consumer.OAuthConsumerRegistry;

import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Created by tuyennt on 12/3/14.
 */
public class OAuthConsumerRegistryImpl implements OAuthConsumerRegistry {
    private final String oauthConfigPrefix;
    private final ConcurrentMap<String, OAuthConsumer> consumers = new ConcurrentHashMap<String, OAuthConsumer>();
    public OAuthConsumerRegistryImpl(InitParams params) {
        ValueParam prefixKey = params == null ? null : params.getValueParam("prefixKey");
        if(prefixKey != null) {
            oauthConfigPrefix = prefixKey.getValue();
        } else {
            oauthConfigPrefix = "gatein.oauth";
        }
    }
    @Override
    public OAuthConsumer getConsumer(String name) {
        if(name == null) {
            return null;
        }
        if(this.consumers.containsKey(name)) {
            return this.consumers.get(name);
        }
        OAuthConsumer consumer = loadConsumer(name);
        if(consumer != null) {
            this.consumers.put(name, consumer);
        }
        return consumer;
    }

    private OAuthConsumer loadConsumer(String name) {
        String prefix = oauthConfigPrefix + "." + name;
        PropertiesHelper p = new PropertiesHelper(PrivilegedSystemHelper.getProperties(), prefix);
        String enable = p.get("enable", "false");
        if(enable.equals("true")) {
            String apiKey = p.get("apiKey");
            String apiSecret = p.get("apiSecret");
            return new OAuthConsumer(name, apiKey, apiSecret, p.getProperties());
        }
        return null;
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
