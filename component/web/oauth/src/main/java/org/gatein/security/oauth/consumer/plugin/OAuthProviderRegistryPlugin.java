package org.gatein.security.oauth.consumer.plugin;

import org.exoplatform.container.component.BaseComponentPlugin;
import org.gatein.security.oauth.consumer.OAuthProvider;
import java.util.Map;

/**
 * Created by tuyennt on 12/11/14.
 */
public abstract class OAuthProviderRegistryPlugin extends BaseComponentPlugin {
    public abstract Map<String, OAuthProvider> getProviders();
}
