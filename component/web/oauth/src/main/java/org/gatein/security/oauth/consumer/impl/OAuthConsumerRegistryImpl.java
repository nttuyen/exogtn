package org.gatein.security.oauth.consumer.impl;

import org.exoplatform.commons.utils.PrivilegedSystemHelper;
import org.exoplatform.container.component.ComponentPlugin;
import org.exoplatform.container.xml.InitParams;
import org.exoplatform.container.xml.ValueParam;
import org.gatein.security.oauth.consumer.OAuthConsumer;
import org.gatein.security.oauth.consumer.OAuthConsumerRegistry;
import org.gatein.security.oauth.consumer.plugin.OAuthConsumerRegistryPlugin;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Created by tuyennt on 12/3/14.
 */
public class OAuthConsumerRegistryImpl implements OAuthConsumerRegistry {
    private final Map<String, OAuthConsumer> consumers = new ConcurrentHashMap<String, OAuthConsumer>();
    public OAuthConsumerRegistryImpl() {

    }
    @Override
    public OAuthConsumer getConsumer(String name) {
        if(name == null) {
            return null;
        }
        return this.consumers.get(name);
    }

    @Override
    public List<OAuthConsumer> getConsumers() {
        if(this.consumers != null) {
            new LinkedList<OAuthConsumer>(this.consumers.values());
        }
        return Collections.emptyList();
    }

    public void addOAuthConsumer(ComponentPlugin p) {
        if(p instanceof OAuthConsumerRegistryPlugin) {
            OAuthConsumerRegistryPlugin plugin = (OAuthConsumerRegistryPlugin)p;
            Map<String, OAuthConsumer> cs = plugin.getConsumers();
            if(cs != null) {
                this.consumers.putAll(cs);
            }
        }
    }
}
