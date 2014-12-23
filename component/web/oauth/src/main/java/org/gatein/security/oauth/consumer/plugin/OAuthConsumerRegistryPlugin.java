package org.gatein.security.oauth.consumer.plugin;

import org.exoplatform.container.component.BaseComponentPlugin;
import org.gatein.pc.portlet.container.managed.LifeCycleStatus;
import org.gatein.security.oauth.consumer.OAuthConsumer;

import java.util.List;
import java.util.Map;

/**
 * Created by tuyennt on 12/11/14.
 */
public abstract class OAuthConsumerRegistryPlugin extends BaseComponentPlugin {
    public abstract Map<String, OAuthConsumer> getConsumers();
}
