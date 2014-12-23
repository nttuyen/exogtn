package org.gatein.security.oauth.consumer.impl;

import org.exoplatform.container.component.ComponentPlugin;
import org.gatein.security.oauth.consumer.OAuthProvider;
import org.gatein.security.oauth.consumer.OAuthProviderRegistry;
import org.gatein.security.oauth.consumer.plugin.OAuthProviderRegistryPlugin;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by tuyennt on 12/11/14.
 */
public class OAuthProviderRegistryImpl implements OAuthProviderRegistry {
    private final Map<String, OAuthProvider> providers = new HashMap<String, OAuthProvider>();

    @Override
    public OAuthProvider getProvider(String name) {
        if(name == null) {
            return null;
        }
        return providers.get(name);
    }

    public void addOAuthProvider(ComponentPlugin plugin) {
        if(plugin instanceof OAuthProviderRegistryPlugin) {
            OAuthProviderRegistryPlugin p = (OAuthProviderRegistryPlugin)plugin;
            Map<String, OAuthProvider> map = p.getProviders();
            if(map != null) {
                providers.putAll(p.getProviders());
            }
        }
    }
}
