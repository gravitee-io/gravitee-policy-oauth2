/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.oauth2;

import io.gravitee.policy.api.PolicyContext;
import io.gravitee.policy.api.PolicyContextProvider;
import io.gravitee.policy.api.PolicyContextProviderAware;
import io.gravitee.policy.api.annotations.properties.Property;
import io.gravitee.policy.oauth2.spring.Oauth2Configuration;
import org.springframework.context.annotation.Import;

/**
 * @author David BRASSELY (david at gravitee.io)
 * @author GraviteeSource Team
 */
@Import({Oauth2Configuration.class})
public class OAuth2PolicyContext implements PolicyContext, PolicyContextProviderAware {

    @Property(name = "oauth.server", required = true)
    private String oauthServer;

    private PolicyContextProvider policyContextProvider;

    public String getOauthServer() {
        return oauthServer;
    }

    public void setOauthServer(String oauthServer) {
        this.oauthServer = oauthServer;
    }

    @Override
    public void onActivation() {
        HttpClient client = policyContextProvider.getComponent(HttpClient.class);
        client.init();
    }

    @Override
    public void onDeactivation() {
        HttpClient client = policyContextProvider.getComponent(HttpClient.class);
        client.close();
    }

    @Override
    public void setPolicyContextProviderAware(PolicyContextProvider policyContextProvider) {
        this.policyContextProvider = policyContextProvider;
    }

    public <T> T getComponent(Class<T> clazz) {
        return policyContextProvider.getComponent(clazz);
    }
}
