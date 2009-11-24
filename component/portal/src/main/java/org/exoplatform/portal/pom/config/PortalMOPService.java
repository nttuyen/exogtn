/*
 * Copyright (C) 2003-2007 eXo Platform SAS.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Affero General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see<http://www.gnu.org/licenses/>.
 */
package org.exoplatform.portal.pom.config;

import org.chromattic.api.ChromatticBuilder;
import org.chromattic.apt.InstrumentorImpl;
import org.exoplatform.portal.pom.registry.CategoryDefinition;
import org.exoplatform.portal.pom.registry.ContentDefinition;
import org.exoplatform.portal.pom.registry.ContentRegistry;
import org.exoplatform.portal.pom.spi.gadget.Gadget;
import org.exoplatform.portal.pom.spi.gadget.GadgetContentProvider;
import org.exoplatform.portal.pom.spi.gadget.GadgetState;
import org.exoplatform.portal.pom.spi.portlet.Portlet;
import org.exoplatform.portal.pom.spi.portlet.PortletContentProvider;
import org.exoplatform.portal.pom.spi.portlet.PortletState;
import org.exoplatform.portal.pom.spi.portlet.PreferenceState;
import org.exoplatform.portal.pom.spi.wsrp.WSRP;
import org.exoplatform.portal.pom.spi.wsrp.WSRPContentProvider;
import org.exoplatform.portal.pom.spi.wsrp.WSRPState;
import org.gatein.mop.core.api.MOPService;
import org.gatein.mop.core.api.content.ContentManagerRegistry;

/**
 * @author <a href="mailto:julien.viet@exoplatform.com">Julien Viet</a>
 * @version $Revision$
 */
public class PortalMOPService extends MOPService
{

   @Override
   protected void configure(ChromatticBuilder builder)
   {
      builder.setOption(ChromatticBuilder.SESSION_LIFECYCLE_CLASSNAME, PortalSessionLifeCycle.class.getName());
      builder.setOption(ChromatticBuilder.INSTRUMENTOR_CLASSNAME, InstrumentorImpl.class.getName());

      //
      builder.add(PortletState.class);
      builder.add(PreferenceState.class);
      builder.add(GadgetState.class);
      builder.add(WSRPState.class);

      //
      builder.add(ContentRegistry.class);
      builder.add(CategoryDefinition.class);
      builder.add(ContentDefinition.class);
   }

   @Override
   protected void configure(ContentManagerRegistry registry)
   {
      registry.register(Portlet.CONTENT_TYPE, new PortletContentProvider());
      registry.register(Gadget.CONTENT_TYPE, new GadgetContentProvider());
      registry.register(WSRP.CONTENT_TYPE, new WSRPContentProvider());
   }
}
