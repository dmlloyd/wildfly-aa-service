/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.auth.client;

import java.security.Principal;

import org.wildfly.security.auth.client.AuthenticationConfiguration.UserSetting;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.sasl.localuser.LocalUserSaslFactory;

class SetLocalUserAuthenticationConfiguration extends AuthenticationConfiguration implements UserSetting {

    static final NamePrincipal localName = new NamePrincipal("$local");

    SetLocalUserAuthenticationConfiguration(final AuthenticationConfiguration parent) {
        super(parent.without(UserSetting.class, SetCallbackHandlerAuthenticationConfiguration.class));
    }

    boolean saslSupportedByConfiguration(final String mechanismName) {
        return LocalUserSaslFactory.JBOSS_LOCAL_USER.equals(mechanismName) || super.saslSupportedByConfiguration(mechanismName);
    }

    Principal getPrincipal() {
        return localName;
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new SetLocalUserAuthenticationConfiguration(newParent);
    }

    boolean halfEqual(final AuthenticationConfiguration other) {
        return other.delegatesThrough(SetLocalUserAuthenticationConfiguration.class) && parentHalfEqual(other);
    }

    int calcHashCode() {
        return Util.hashiply(parentHashCode(), 19273, 0);
    }

    @Override
    StringBuilder asString(StringBuilder sb) {
        return parentAsString(sb).append("LocalAuthentication,");
    }

}
