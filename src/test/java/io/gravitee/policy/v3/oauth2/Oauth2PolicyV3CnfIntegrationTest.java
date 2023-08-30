/*
 * Copyright © 2015 The Gravitee team (http://gravitee.io)
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
package io.gravitee.policy.v3.oauth2;

import static io.gravitee.definition.model.ExecutionMode.V3;
import static org.mockito.Mockito.when;

import io.gravitee.apim.gateway.tests.sdk.annotations.DeployApi;
import io.gravitee.apim.gateway.tests.sdk.annotations.GatewayTest;
import io.gravitee.gateway.api.service.Subscription;
import io.gravitee.gateway.api.service.SubscriptionService;
import io.gravitee.policy.oauth2.Oauth2PolicyV4EmulationEngineCnfIntegrationTest;
import java.util.Optional;
import org.junit.jupiter.api.Nested;
import org.mockito.stubbing.OngoingStubbing;

/**
 * @author GraviteeSource Team
 */
public class Oauth2PolicyV3CnfIntegrationTest {

    @Nested
    @DeployApi("/apis/oauth2.json")
    @GatewayTest(v2ExecutionMode = V3)
    public class Oauth2PolicyV3MissingCnfIntegrationTest
        extends Oauth2PolicyV4EmulationEngineCnfIntegrationTest.AbstractOauth2PolicyMissingCnfIntegrationTest {

        /**
         * This overrides subscription search :
         * - in jupiter its searched with getByApiAndSecurityToken
         * - in V3 its searches with api/clientId/plan
         */
        protected OngoingStubbing<Optional<Subscription>> whenSearchingSubscription(String api, String clientId, String plan) {
            return when(getBean(SubscriptionService.class).getByApiAndClientIdAndPlan(api, clientId, plan));
        }
    }

    @Nested
    @DeployApi("/apis/oauth2.json")
    @GatewayTest(v2ExecutionMode = V3)
    public class Oauth2PolicyV3CnfHeaderCertificateIntegrationTest
        extends Oauth2PolicyV4EmulationEngineCnfIntegrationTest.AbstractOauth2PolicyCnfHeaderCertificateIntegrationTest {

        /**
         * This overrides subscription search :
         * - in jupiter its searched with getByApiAndSecurityToken
         * - in V3 its searches with api/clientId/plan
         */
        @Override
        protected OngoingStubbing<Optional<Subscription>> whenSearchingSubscription(String api, String clientId, String plan) {
            return when(getBean(SubscriptionService.class).getByApiAndClientIdAndPlan(api, clientId, plan));
        }
    }

    @Nested
    @DeployApi("/apis/oauth2.json")
    @GatewayTest(v2ExecutionMode = V3)
    public class Oauth2PolicyV3CnfPeerCertificateIntegrationTest
        extends Oauth2PolicyV4EmulationEngineCnfIntegrationTest.AbstractOauth2PolicyCnfPeerCertificateIntegrationTest {

        /**
         * This overrides subscription search :
         * - in jupiter its searched with getByApiAndSecurityToken
         * - in V3 its searches with api/clientId/plan
         */
        @Override
        protected OngoingStubbing<Optional<Subscription>> whenSearchingSubscription(String api, String clientId, String plan) {
            return when(getBean(SubscriptionService.class).getByApiAndClientIdAndPlan(api, clientId, plan));
        }
    }

    @Nested
    @DeployApi("/apis/oauth2.json")
    @GatewayTest(v2ExecutionMode = V3)
    public class Oauth2PolicyV3CnfInvalidPeerCertificateIntegrationTest
        extends Oauth2PolicyV4EmulationEngineCnfIntegrationTest.AbstractOauth2PolicyCnfInvalidPeerCertificateIntegrationTest {

        /**
         * This overrides subscription search :
         * - in jupiter its searched with getByApiAndSecurityToken
         * - in V3 its searches with api/clientId/plan
         */
        protected OngoingStubbing<Optional<Subscription>> whenSearchingSubscription(String api, String clientId, String plan) {
            return when(getBean(SubscriptionService.class).getByApiAndClientIdAndPlan(api, clientId, plan));
        }
    }
}
