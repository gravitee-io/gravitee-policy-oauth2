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
package io.gravitee.policy.oauth2;

import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.ok;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.gravitee.apim.gateway.tests.sdk.AbstractPolicyTest;
import io.gravitee.apim.gateway.tests.sdk.annotations.DeployApi;
import io.gravitee.apim.gateway.tests.sdk.annotations.GatewayTest;
import io.gravitee.apim.gateway.tests.sdk.parameters.GatewayDynamicConfig;
import io.gravitee.apim.gateway.tests.sdk.resource.ResourceBuilder;
import io.gravitee.definition.model.v4.Api;
import io.gravitee.definition.model.v4.plan.PlanMode;
import io.gravitee.definition.model.v4.plan.PlanSecurity;
import io.gravitee.definition.model.v4.plan.PlanStatus;
import io.gravitee.gateway.reactor.ReactableApi;
import io.gravitee.plugin.resource.ResourcePlugin;
import io.gravitee.policy.oauth2.configuration.OAuth2PolicyConfiguration;
import io.gravitee.resource.oauth2.api.OAuth2ResourceMetadata;
import io.reactivex.rxjava3.core.Single;
import io.vertx.core.http.HttpMethod;
import io.vertx.rxjava3.core.http.HttpClient;
import io.vertx.rxjava3.core.http.HttpClientRequest;
import io.vertx.rxjava3.core.http.HttpClientResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * @author GraviteeSource Team
 */
@GatewayTest
@DeployApi("/apis/oauth2-v4.json")
public class Oauth2PolicyV4IntegrationTest extends AbstractPolicyTest<Oauth2Policy, OAuth2PolicyConfiguration> {

    public static final String PLAN_ID = "plan-id";
    private static final ObjectMapper mapper = new ObjectMapper();

    @Override
    public void configureResources(Map<String, ResourcePlugin> resources) {
        resources.put("dummy-oauth2-resource", ResourceBuilder.build("dummy-oauth2-resource", DummyOAuth2Resource.class));
    }

    @Override
    public void configureApi(ReactableApi<?> api, Class<?> definitionClass) {
        final io.gravitee.definition.model.v4.Api apiDefinition = (Api) api.getDefinition();

        OAuth2PolicyConfiguration configuration = new OAuth2PolicyConfiguration();
        configuration.setOauthResource("dummy-oauth2-resource");
        configuration.setAddWwwAuthenticateHeader(true);

        String configurationString = null;
        try {
            configurationString = new ObjectMapper().writeValueAsString(configuration);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }

        io.gravitee.definition.model.v4.plan.Plan oauth2Plan = io.gravitee.definition.model.v4.plan.Plan
            .builder()
            .id(PLAN_ID)
            .name("plan-name")
            .security(PlanSecurity.builder().type("oauth2").configuration(configurationString).build())
            .status(PlanStatus.PUBLISHED)
            .mode(PlanMode.STANDARD)
            .build();

        List<io.gravitee.definition.model.v4.plan.Plan> plans = new ArrayList<>();
        plans.add(oauth2Plan);
        apiDefinition.setPlans(plans);
    }

    @Test
    @DisplayName("Should receive the OAuth2 resource metadata response when calling the '/.well-known/oauth-protected-resource' endpoint")
    void shouldGetOAuth2ResourceMetadata(HttpClient client, GatewayDynamicConfig.HttpConfig gatewayConfig) throws InterruptedException {
        Single<HttpClientResponse> httpClientResponse = client
            .rxRequest(HttpMethod.GET, "/test/.well-known/oauth-protected-resource")
            .flatMap(HttpClientRequest::rxSend);
        httpClientResponse
            .flatMapPublisher(response -> {
                assertThat(response.statusCode()).isEqualTo(200);
                return response.body().toFlowable();
            })
            .test()
            .await()
            .assertComplete()
            .assertValue(body -> {
                OAuth2ResourceMetadata resourceMetadata = mapper.readValue(body.toString(), OAuth2ResourceMetadata.class);
                assertAll(
                    () ->
                        assertThat(resourceMetadata.protectedResourceUri())
                            .isEqualTo("http://localhost:" + gatewayConfig.httpPort() + "/test/"),
                    () -> assertThat(resourceMetadata.authorizationServers()).isEqualTo(List.of("https://some.keycloak.com/realms/test")),
                    () -> assertThat(resourceMetadata.scopesSupported()).containsExactlyInAnyOrder("read", "write")
                );
                return true;
            })
            .assertNoErrors();

        wiremock.verify(0, getRequestedFor(urlPathEqualTo("/team")));
    }

    @Test
    @DisplayName("Should receive 401 - Unauthorized when calling without any Authorization Header")
    void shouldGet401_ifNoToken(HttpClient client, GatewayDynamicConfig.HttpConfig gatewayConfig) throws InterruptedException {
        wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

        Single<HttpClientResponse> httpClientResponse = client.rxRequest(HttpMethod.GET, "/test").flatMap(HttpClientRequest::rxSend);

        httpClientResponse
            .flatMapPublisher(response -> {
                assertThat(response.statusCode()).isEqualTo(401);
                String wwwAuthenticateHeader = String.format(
                    "Bearer resource_metadata=\"http://localhost:%s/test/.well-known/oauth-protected-resource\"",
                    gatewayConfig.httpPort()
                );
                assertThat(response.headers().get("WWW-Authenticate")).isEqualTo(wwwAuthenticateHeader);
                return response.body().toFlowable();
            })
            .test()
            .await()
            .assertComplete()
            .assertValue(body -> {
                assertThat(body.toString()).isEqualTo("Unauthorized");
                return true;
            })
            .assertNoErrors();

        wiremock.verify(0, getRequestedFor(urlPathEqualTo("/team")));
    }
}
