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
import static io.gravitee.policy.oauth2.DummyOAuth2Resource.CLIENT_ID;
import static java.util.concurrent.TimeUnit.HOURS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import io.gravitee.apim.gateway.tests.sdk.AbstractPolicyTest;
import io.gravitee.apim.gateway.tests.sdk.annotations.DeployApi;
import io.gravitee.apim.gateway.tests.sdk.annotations.GatewayTest;
import io.gravitee.apim.gateway.tests.sdk.configuration.GatewayConfigurationBuilder;
import io.gravitee.apim.gateway.tests.sdk.resource.ResourceBuilder;
import io.gravitee.definition.model.Api;
import io.gravitee.definition.model.Plan;
import io.gravitee.gateway.api.service.Subscription;
import io.gravitee.gateway.api.service.SubscriptionService;
import io.gravitee.gateway.reactive.api.policy.SecurityToken;
import io.gravitee.plugin.resource.ResourcePlugin;
import io.gravitee.policy.oauth2.configuration.OAuth2PolicyConfiguration;
import io.gravitee.policy.v3.oauth2.Oauth2PolicyV3IntegrationTest;
import io.reactivex.rxjava3.core.Single;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.net.PemKeyCertOptions;
import io.vertx.rxjava3.core.http.HttpClient;
import io.vertx.rxjava3.core.http.HttpClientResponse;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.stubbing.OngoingStubbing;

/**
 * @author GraviteeSource Team
 */
public class Oauth2PolicyV4EmulationEngineCnfIntegrationTest {

    public static final String API_ID = "my-api";
    public static final String PLAN_ID = "plan-id";

    public static void configureHttpClient(HttpClientOptions options, int gatewayPort) {
        options.setDefaultHost("localhost").setDefaultPort(gatewayPort).setSsl(true).setVerifyHost(false).setTrustAll(true);
    }

    public static void configureGateway(GatewayConfigurationBuilder gatewayConfigurationBuilder) {
        gatewayConfigurationBuilder
            .set("http.secured", true)
            .set("http.alpn", true)
            .set("http.ssl.keystore.type", "self-signed")
            .set("http.ssl.clientAuth", "request")
            .set("http.ssl.truststore.type", "pkcs12")
            .set("http.ssl.truststore.path", Oauth2PolicyV3IntegrationTest.class.getResource("/certificate/keystore.p12").getPath())
            .set("http.ssl.truststore.password", "gravitee");
    }

    public static void configureResources(Map<String, ResourcePlugin> resources) {
        resources.put("dummy-oauth2-resource", ResourceBuilder.build("dummy-oauth2-resource", DummyOAuth2Resource.class));
    }

    public static Subscription fakeSubscriptionFromCache(boolean isExpired) {
        final Subscription subscription = new Subscription();
        subscription.setApplication("application-id");
        subscription.setId("subscription-id");
        subscription.setPlan(PLAN_ID);
        if (isExpired) {
            subscription.setEndingAt(new Date(Instant.now().minus(1, HOURS.toChronoUnit()).toEpochMilli()));
        }
        return subscription;
    }

    public static SecurityToken securityTokenMatcher(String clientId) {
        return argThat(securityToken ->
            securityToken.getTokenType().equals(SecurityToken.TokenType.CLIENT_ID.name()) && securityToken.getTokenValue().equals(clientId)
        );
    }

    public static Plan createOauth2Plan(final Api api) {
        Plan oauth2Plan = new Plan();
        oauth2Plan.setId(PLAN_ID);
        oauth2Plan.setApi(api.getId());
        oauth2Plan.setSecurity("OAUTH2");
        oauth2Plan.setStatus("PUBLISHED");
        return oauth2Plan;
    }

    public static void assert401unauthorized(WireMockServer wiremock, Single<HttpClientResponse> httpClientResponse)
        throws InterruptedException {
        httpClientResponse
            .flatMapPublisher(response -> {
                assertThat(response.statusCode()).isEqualTo(401);
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

    @Nested
    @GatewayTest
    @DeployApi("/apis/oauth2.json")
    public class Oauth2PolicyV4EmulationEngineMissingCnfIntegrationTest extends AbstractOauth2PolicyMissingCnfIntegrationTest {}

    public static class AbstractOauth2PolicyMissingCnfIntegrationTest extends AbstractPolicyTest<Oauth2Policy, OAuth2PolicyConfiguration> {

        @Override
        public void configureGateway(GatewayConfigurationBuilder gatewayConfigurationBuilder) {
            Oauth2PolicyV4EmulationEngineCnfIntegrationTest.configureGateway(gatewayConfigurationBuilder);
        }

        @Override
        protected void configureHttpClient(final HttpClientOptions options) {
            Oauth2PolicyV4EmulationEngineCnfIntegrationTest.configureHttpClient(options, gatewayPort());
        }

        @Override
        public void configureApi(final Api api) {
            Plan oauth2Plan = createOauth2Plan(api);

            OAuth2PolicyConfiguration configuration = new OAuth2PolicyConfiguration();
            configuration.setOauthResource("dummy-oauth2-resource");
            configuration.getConfirmationMethodValidation().setIgnoreMissing(true);
            configuration.getConfirmationMethodValidation().getCertificateBoundThumbprint().setEnabled(true);

            try {
                oauth2Plan.setSecurityDefinition(new ObjectMapper().writeValueAsString(configuration));
            } catch (JsonProcessingException e) {
                throw new RuntimeException("Failed to set OAuth2 policy configuration", e);
            }

            api.setPlans(Collections.singletonList(oauth2Plan));
        }

        @Override
        public void configureResources(final Map<String, ResourcePlugin> resources) {
            Oauth2PolicyV4EmulationEngineCnfIntegrationTest.configureResources(resources);
        }

        @Test
        void should_access_api_and_ignore_missing_cnf(HttpClient client) throws InterruptedException {
            wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

            // subscription found is valid
            whenSearchingSubscription(API_ID, CLIENT_ID, PLAN_ID).thenReturn(Optional.of(fakeSubscriptionFromCache(false)));

            client
                .rxRequest(HttpMethod.GET, "/test")
                .flatMap(request ->
                    request.putHeader("Authorization", "Bearer " + DummyOAuth2Resource.TOKEN_SUCCESS_WITH_CLIENT_ID).rxSend()
                )
                .flatMapPublisher(response -> {
                    assertThat(response.statusCode()).isEqualTo(200);
                    return response.toFlowable();
                })
                .test()
                .await()
                .assertComplete()
                .assertValue(body -> {
                    assertThat(body).hasToString("response from backend");
                    return true;
                })
                .assertNoErrors();

            wiremock.verify(1, getRequestedFor(urlPathEqualTo("/team")));
        }

        protected OngoingStubbing<Optional<Subscription>> whenSearchingSubscription(String api, String clientId, String plan) {
            return when(getBean(SubscriptionService.class).getByApiAndSecurityToken(eq(api), securityTokenMatcher(clientId), eq(plan)));
        }
    }

    @Nested
    @DeployApi("/apis/oauth2.json")
    @GatewayTest
    public class Oauth2PolicyV4EmulationEngineCnfHeaderCertificateIntegrationTest
        extends AbstractOauth2PolicyCnfHeaderCertificateIntegrationTest {}

    public static class AbstractOauth2PolicyCnfHeaderCertificateIntegrationTest
        extends AbstractPolicyTest<Oauth2Policy, OAuth2PolicyConfiguration> {

        @Override
        public void configureGateway(GatewayConfigurationBuilder gatewayConfigurationBuilder) {
            Oauth2PolicyV4EmulationEngineCnfIntegrationTest.configureGateway(gatewayConfigurationBuilder);
        }

        @Override
        protected void configureHttpClient(final HttpClientOptions options) {
            Oauth2PolicyV4EmulationEngineCnfIntegrationTest.configureHttpClient(options, gatewayPort());
        }

        @Override
        public void configureApi(final Api api) {
            Plan oauth2Plan = createOauth2Plan(api);

            OAuth2PolicyConfiguration configuration = new OAuth2PolicyConfiguration();
            configuration.setOauthResource("dummy-oauth2-resource");
            configuration.getConfirmationMethodValidation().getCertificateBoundThumbprint().setEnabled(true);
            configuration.getConfirmationMethodValidation().getCertificateBoundThumbprint().setExtractCertificateFromHeader(true);
            try {
                oauth2Plan.setSecurityDefinition(new ObjectMapper().writeValueAsString(configuration));
            } catch (JsonProcessingException e) {
                throw new RuntimeException("Failed to set OAuth2 policy configuration", e);
            }

            api.setPlans(Collections.singletonList(oauth2Plan));
        }

        @Override
        public void configureResources(final Map<String, ResourcePlugin> resources) {
            Oauth2PolicyV4EmulationEngineCnfIntegrationTest.configureResources(resources);
        }

        @Test
        void should_access_api_with_valid_certificate_from_header(HttpClient client)
            throws InterruptedException, URISyntaxException, IOException {
            wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

            // subscription found is valid
            whenSearchingSubscription(API_ID, CLIENT_ID, PLAN_ID).thenReturn(Optional.of(fakeSubscriptionFromCache(false)));

            String clientCert = Files.readString(
                Paths.get(Oauth2PolicyV3IntegrationTest.class.getResource("/certificate/client1-crt.pem").toURI())
            );
            String encoded = URLEncoder.encode(clientCert, Charset.defaultCharset());

            client
                .rxRequest(HttpMethod.GET, "/test")
                .flatMap(request ->
                    request
                        .putHeader("Authorization", "Bearer " + DummyOAuth2Resource.TOKEN_SUCCESS_WITH_CNF)
                        .putHeader("ssl-client-cert", encoded)
                        .rxSend()
                )
                .flatMapPublisher(response -> {
                    assertThat(response.statusCode()).isEqualTo(200);
                    return response.toFlowable();
                })
                .test()
                .await()
                .assertComplete()
                .assertValue(body -> {
                    assertThat(body).hasToString("response from backend");
                    return true;
                })
                .assertNoErrors();

            wiremock.verify(1, getRequestedFor(urlPathEqualTo("/team")));
        }

        @Test
        void should_return_401_without_valid_certificate_in_header(HttpClient client) throws InterruptedException {
            wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

            // subscription found is valid
            whenSearchingSubscription(API_ID, CLIENT_ID, PLAN_ID).thenReturn(Optional.of(fakeSubscriptionFromCache(false)));

            Single<HttpClientResponse> httpClientResponse = client
                .rxRequest(HttpMethod.GET, "/test")
                .flatMap(request ->
                    request
                        .putHeader("Authorization", "Bearer " + DummyOAuth2Resource.TOKEN_SUCCESS_WITH_CNF)
                        .putHeader("ssl-client-cert", "wrong")
                        .rxSend()
                );

            assert401unauthorized(wiremock, httpClientResponse);
        }

        @Test
        void should_return_401_with_valid_certificate_in_header_but_without_cnf_in_token(HttpClient client)
            throws InterruptedException, URISyntaxException, IOException {
            wiremock.stubFor(get("/team").willReturn(ok("response from backend")));
            // subscription found is valid
            whenSearchingSubscription(API_ID, CLIENT_ID, PLAN_ID).thenReturn(Optional.of(fakeSubscriptionFromCache(false)));

            String clientCert = Files.readString(
                Paths.get(Oauth2PolicyV3IntegrationTest.class.getResource("/certificate/client1-crt.pem").toURI())
            );
            String encoded = URLEncoder.encode(clientCert, Charset.defaultCharset());

            Single<HttpClientResponse> httpClientResponse = client
                .rxRequest(HttpMethod.GET, "/test")
                .flatMap(request ->
                    request
                        .putHeader("Authorization", "Bearer " + DummyOAuth2Resource.TOKEN_SUCCESS_WITH_CLIENT_ID)
                        .putHeader("ssl-client-cert", encoded)
                        .rxSend()
                );

            assert401unauthorized(wiremock, httpClientResponse);
        }

        protected OngoingStubbing<Optional<Subscription>> whenSearchingSubscription(String api, String clientId, String plan) {
            return when(getBean(SubscriptionService.class).getByApiAndSecurityToken(eq(api), securityTokenMatcher(clientId), eq(plan)));
        }
    }

    @Nested
    @DeployApi("/apis/oauth2.json")
    @GatewayTest
    public class Oauth2PolicyV4EmulationEngineCnfPeerCertificateIntegrationTest
        extends AbstractOauth2PolicyCnfPeerCertificateIntegrationTest {}

    public static class AbstractOauth2PolicyCnfPeerCertificateIntegrationTest
        extends AbstractPolicyTest<Oauth2Policy, OAuth2PolicyConfiguration> {

        @Override
        public void configureGateway(GatewayConfigurationBuilder gatewayConfigurationBuilder) {
            Oauth2PolicyV4EmulationEngineCnfIntegrationTest.configureGateway(gatewayConfigurationBuilder);
        }

        @Override
        protected void configureHttpClient(final HttpClientOptions options) {
            Oauth2PolicyV4EmulationEngineCnfIntegrationTest.configureHttpClient(options, gatewayPort());

            final PemKeyCertOptions pemKeyCertOptions = new PemKeyCertOptions();
            pemKeyCertOptions.setCertPath(Oauth2PolicyV3IntegrationTest.class.getResource("/certificate/client1-crt.pem").getPath());
            pemKeyCertOptions.setKeyPath(Oauth2PolicyV3IntegrationTest.class.getResource("/certificate/client1-key.pem").getPath());
            options.setPemKeyCertOptions(pemKeyCertOptions);
        }

        @Override
        public void configureApi(final Api api) {
            Plan oauth2Plan = createOauth2Plan(api);

            OAuth2PolicyConfiguration configuration = new OAuth2PolicyConfiguration();
            configuration.setOauthResource("dummy-oauth2-resource");
            configuration.getConfirmationMethodValidation().getCertificateBoundThumbprint().setEnabled(true);
            try {
                oauth2Plan.setSecurityDefinition(new ObjectMapper().writeValueAsString(configuration));
            } catch (JsonProcessingException e) {
                throw new RuntimeException("Failed to set OAuth2 policy configuration", e);
            }

            api.setPlans(Collections.singletonList(oauth2Plan));
        }

        @Override
        public void configureResources(final Map<String, ResourcePlugin> resources) {
            Oauth2PolicyV4EmulationEngineCnfIntegrationTest.configureResources(resources);
        }

        @Test
        void should_access_api_with_valid_certificate_from_ssl_session(HttpClient client)
            throws InterruptedException, URISyntaxException, IOException {
            wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

            // subscription found is valid
            whenSearchingSubscription(API_ID, CLIENT_ID, PLAN_ID).thenReturn(Optional.of(fakeSubscriptionFromCache(false)));

            client
                .rxRequest(HttpMethod.GET, "/test")
                .flatMap(request -> request.putHeader("Authorization", "Bearer " + DummyOAuth2Resource.TOKEN_SUCCESS_WITH_CNF).rxSend())
                .flatMapPublisher(response -> {
                    assertThat(response.statusCode()).isEqualTo(200);
                    return response.toFlowable();
                })
                .test()
                .await()
                .assertComplete()
                .assertValue(body -> {
                    assertThat(body).hasToString("response from backend");
                    return true;
                })
                .assertNoErrors();

            wiremock.verify(1, getRequestedFor(urlPathEqualTo("/team")));
        }

        @Test
        void should_return_401_with_valid_certificate_from_ssl_session_but_without_cnf_in_token(HttpClient client)
            throws InterruptedException {
            wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

            // subscription found is valid
            whenSearchingSubscription(API_ID, CLIENT_ID, PLAN_ID).thenReturn(Optional.of(fakeSubscriptionFromCache(false)));

            Single<HttpClientResponse> httpClientResponse = client
                .rxRequest(HttpMethod.GET, "/test")
                .flatMap(request ->
                    request.putHeader("Authorization", "Bearer " + DummyOAuth2Resource.TOKEN_SUCCESS_WITH_CLIENT_ID).rxSend()
                );

            assert401unauthorized(wiremock, httpClientResponse);
        }

        protected OngoingStubbing<Optional<Subscription>> whenSearchingSubscription(String api, String clientId, String plan) {
            return when(getBean(SubscriptionService.class).getByApiAndSecurityToken(eq(api), securityTokenMatcher(clientId), eq(plan)));
        }
    }

    @Nested
    @DeployApi("/apis/oauth2.json")
    @GatewayTest
    public class Oauth2PolicyV4EmulationEngineCnfInvalidPeerCertificateIntegrationTest
        extends AbstractOauth2PolicyCnfInvalidPeerCertificateIntegrationTest {}

    public static class AbstractOauth2PolicyCnfInvalidPeerCertificateIntegrationTest
        extends AbstractPolicyTest<Oauth2Policy, OAuth2PolicyConfiguration> {

        @Override
        public void configureGateway(GatewayConfigurationBuilder gatewayConfigurationBuilder) {
            Oauth2PolicyV4EmulationEngineCnfIntegrationTest.configureGateway(gatewayConfigurationBuilder);
        }

        @Override
        protected void configureHttpClient(final HttpClientOptions options) {
            Oauth2PolicyV4EmulationEngineCnfIntegrationTest.configureHttpClient(options, gatewayPort());
        }

        @Override
        public void configureApi(final Api api) {
            Plan oauth2Plan = createOauth2Plan(api);

            OAuth2PolicyConfiguration configuration = new OAuth2PolicyConfiguration();
            configuration.setOauthResource("dummy-oauth2-resource");
            configuration.getConfirmationMethodValidation().getCertificateBoundThumbprint().setEnabled(true);
            try {
                oauth2Plan.setSecurityDefinition(new ObjectMapper().writeValueAsString(configuration));
            } catch (JsonProcessingException e) {
                throw new RuntimeException("Failed to set OAuth2 policy configuration", e);
            }

            api.setPlans(Collections.singletonList(oauth2Plan));
        }

        @Override
        public void configureResources(final Map<String, ResourcePlugin> resources) {
            Oauth2PolicyV4EmulationEngineCnfIntegrationTest.configureResources(resources);
        }

        @Test
        void should_return_401_without_valid_peer_certificate_from_ssl_session(HttpClient client) throws InterruptedException {
            wiremock.stubFor(get("/team").willReturn(ok("response from backend")));

            // subscription found is valid
            whenSearchingSubscription(API_ID, CLIENT_ID, PLAN_ID).thenReturn(Optional.of(fakeSubscriptionFromCache(false)));

            Single<HttpClientResponse> httpClientResponse = client
                .rxRequest(HttpMethod.GET, "/test")
                .flatMap(request ->
                    request.putHeader("Authorization", "Bearer " + DummyOAuth2Resource.TOKEN_SUCCESS_WITH_CLIENT_ID).rxSend()
                );

            assert401unauthorized(wiremock, httpClientResponse);
        }

        protected OngoingStubbing<Optional<Subscription>> whenSearchingSubscription(String api, String clientId, String plan) {
            return when(getBean(SubscriptionService.class).getByApiAndSecurityToken(eq(api), securityTokenMatcher(clientId), eq(plan)));
        }
    }
}
