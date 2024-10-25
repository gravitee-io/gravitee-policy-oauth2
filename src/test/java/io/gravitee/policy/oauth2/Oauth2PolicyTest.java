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

import static io.gravitee.gateway.api.ExecutionContext.ATTR_USER;
import static io.gravitee.gateway.api.ExecutionContext.ATTR_USER_ROLES;
import static io.gravitee.gateway.api.http.HttpHeaderNames.AUTHORIZATION;
import static io.gravitee.policy.oauth2.Oauth2Policy.CONTEXT_ATTRIBUTE_JWT;
import static io.gravitee.policy.oauth2.Oauth2Policy.CONTEXT_ATTRIBUTE_OAUTH_ACCESS_TOKEN;
import static io.gravitee.policy.oauth2.Oauth2Policy.CONTEXT_ATTRIBUTE_OAUTH_PAYLOAD;
import static io.gravitee.policy.oauth2.Oauth2Policy.OAUTH2_INSUFFICIENT_SCOPE_KEY;
import static io.gravitee.policy.oauth2.Oauth2Policy.OAUTH2_INVALID_ACCESS_TOKEN_KEY;
import static io.gravitee.policy.oauth2.Oauth2Policy.OAUTH2_INVALID_SERVER_RESPONSE_KEY;
import static io.gravitee.policy.oauth2.Oauth2Policy.OAUTH2_MISSING_ACCESS_TOKEN_KEY;
import static io.gravitee.policy.oauth2.Oauth2Policy.OAUTH2_MISSING_HEADER_KEY;
import static io.gravitee.policy.oauth2.Oauth2Policy.OAUTH2_MISSING_SERVER_KEY;
import static io.gravitee.policy.oauth2.Oauth2Policy.OAUTH2_SERVER_UNAVAILABLE_KEY;
import static io.gravitee.policy.v3.oauth2.Oauth2PolicyV3.OAUTH2_TEMPORARILY_UNAVAILABLE_MESSAGE;
import static io.gravitee.policy.v3.oauth2.Oauth2PolicyV3.OAUTH2_UNAUTHORIZED_MESSAGE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.argThat;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.common.security.jwt.LazyJWT;
import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.api.handler.Handler;
import io.gravitee.gateway.api.http.HttpHeaderNames;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.gateway.reactive.api.ExecutionFailure;
import io.gravitee.gateway.reactive.api.context.GenericExecutionContext;
import io.gravitee.gateway.reactive.api.context.base.BaseExecutionContext;
import io.gravitee.gateway.reactive.api.context.http.HttpPlainExecutionContext;
import io.gravitee.gateway.reactive.api.context.http.HttpPlainRequest;
import io.gravitee.gateway.reactive.api.context.http.HttpPlainResponse;
import io.gravitee.gateway.reactive.api.policy.SecurityToken;
import io.gravitee.gateway.reactive.core.context.DefaultExecutionContext;
import io.gravitee.gateway.reactive.core.context.MutableRequest;
import io.gravitee.gateway.reactive.core.context.MutableResponse;
import io.gravitee.policy.oauth2.configuration.OAuth2PolicyConfiguration;
import io.gravitee.policy.oauth2.introspection.TokenIntrospectionResult;
import io.gravitee.policy.oauth2.resource.CacheElement;
import io.gravitee.reporter.api.v4.metric.Metrics;
import io.gravitee.resource.api.ResourceManager;
import io.gravitee.resource.cache.api.Cache;
import io.gravitee.resource.cache.api.CacheResource;
import io.gravitee.resource.oauth2.api.OAuth2Resource;
import io.gravitee.resource.oauth2.api.OAuth2ResourceException;
import io.gravitee.resource.oauth2.api.OAuth2Response;
import io.reactivex.rxjava3.core.Completable;
import io.reactivex.rxjava3.observers.TestObserver;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
@ExtendWith(MockitoExtension.class)
class Oauth2PolicyTest {

    private static final String DEFAULT_OAUTH_SCOPE_SEPARATOR = " ";

    static final ObjectMapper MAPPER = new ObjectMapper();
    protected static final String OAUTH_RESOURCE = "oauth2";
    protected static final String MOCK_EXCEPTION = "Mock exception";
    protected static final String MOCK_INTROSPECT_EXCEPTION = "Mock introspect exception";
    protected static final String INVALID_PAYLOAD = "blablabla";
    protected static final String OAUTH_CACHE_RESOURCE = "OAUTH_CACHE_RESOURCE";

    @Mock
    private OAuth2PolicyConfiguration configuration;

    @Mock
    private HttpPlainRequest request;

    @Mock
    private HttpPlainResponse response;

    @Mock(extraInterfaces = GenericExecutionContext.class)
    private HttpPlainExecutionContext ctx;

    @Mock
    private ResourceManager resourceManager;

    @Mock
    private OAuth2Resource<?> oAuth2Resource;

    @Mock
    private TemplateEngine templateEngine;

    @Mock
    private CacheResource<?> cacheResource;

    @Mock
    private HttpHeaders headers;

    @Mock
    private HttpHeaders responseHeaders;

    @Mock
    private Cache cache;

    private Oauth2Policy cut;

    @BeforeEach
    void init() {
        // Common lenient mocks.
        lenient().when(ctx.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        lenient().when(ctx.request()).thenReturn(request);
        lenient().when(request.headers()).thenReturn(headers);

        lenient().when(ctx.getTemplateEngine()).thenReturn(templateEngine);

        lenient().when(ctx.response()).thenReturn(response);
        lenient().when(response.headers()).thenReturn(responseHeaders);

        cut = new Oauth2Policy(configuration);
    }

    @Test
    void shouldInterruptWith401IfNoOAuthResourceProvided() {
        when(configuration.getOauthResource()).thenReturn(OAUTH_RESOURCE);

        final TestObserver<Void> obs = cut.onRequest(ctx).test();
        obs.assertError(Throwable.class);

        verifyInterruptWith(HttpStatusCode.UNAUTHORIZED_401, OAUTH2_MISSING_SERVER_KEY, OAUTH2_UNAUTHORIZED_MESSAGE);
    }

    @Test
    void shouldInterruptWith401IfNoAuthorizationHeaderProvided() {
        prepareOauth2Resource();

        final TestObserver<Void> obs = cut.onRequest(ctx).test();
        obs.assertError(Throwable.class);

        verify(responseHeaders).add(eq(HttpHeaderNames.WWW_AUTHENTICATE), anyString());
        verifyInterruptWith(HttpStatusCode.UNAUTHORIZED_401, OAUTH2_MISSING_HEADER_KEY, OAUTH2_UNAUTHORIZED_MESSAGE);
    }

    @Test
    void shouldInterruptWith401IfNoAuthorizationHeaderBearerProvided() {
        when(headers.getAll(AUTHORIZATION)).thenReturn(List.of("Basic Test"));
        prepareOauth2Resource();

        final TestObserver<Void> obs = cut.onRequest(ctx).test();
        obs.assertError(Throwable.class);

        verify(responseHeaders).add(eq(HttpHeaderNames.WWW_AUTHENTICATE), anyString());
        verifyInterruptWith(HttpStatusCode.UNAUTHORIZED_401, OAUTH2_MISSING_HEADER_KEY, OAUTH2_UNAUTHORIZED_MESSAGE);
    }

    @Test
    void shouldInterruptWith401IfNoAuthorizationAccessTokenBearerIsEmptyProvided() {
        when(headers.getAll(AUTHORIZATION)).thenReturn(List.of("Bearer"));
        prepareOauth2Resource();

        final TestObserver<Void> obs = cut.onRequest(ctx).test();
        obs.assertError(Throwable.class);

        verify(responseHeaders).add(eq(HttpHeaderNames.WWW_AUTHENTICATE), anyString());
        verifyInterruptWith(HttpStatusCode.UNAUTHORIZED_401, OAUTH2_MISSING_ACCESS_TOKEN_KEY, OAUTH2_UNAUTHORIZED_MESSAGE);
    }

    @Test
    void shouldCallOAuthResource() throws Exception {
        final String token = prepareToken();
        prepareOauth2Resource();
        prepareIntrospection(token, readResource("/io/gravitee/policy/oauth2/oauth2-response04.json"), true);

        final TestObserver<Void> obs = cut.onRequest(ctx).test();
        obs.assertComplete();

        verify(oAuth2Resource).introspect(eq(token), any(Handler.class));
        verify(ctx).setAttribute(eq(Oauth2Policy.CONTEXT_ATTRIBUTE_OAUTH_ACCESS_TOKEN), eq(token));
        verify(ctx, times(0)).setAttribute(eq(CONTEXT_ATTRIBUTE_OAUTH_PAYLOAD), any());
    }

    @Test
    void shouldInterruptWith401WhenIntrospectionFails() throws IOException {
        final String token = prepareToken();
        prepareOauth2Resource();

        final String payload = readResource("/io/gravitee/policy/oauth2/oauth2-response03.json");
        prepareIntrospection(token, payload, false);

        when(ctx.interruptWith(any(ExecutionFailure.class))).thenReturn(Completable.error(new RuntimeException(MOCK_EXCEPTION)));

        final TestObserver<Void> obs = cut.onRequest(ctx).test();
        obs.assertError(Throwable.class);

        verify(ctx, never()).setAttribute(eq(Oauth2Policy.CONTEXT_ATTRIBUTE_CLIENT_ID), anyString());
        verify(responseHeaders).add(eq(HttpHeaderNames.WWW_AUTHENTICATE), anyString());

        verifyInterruptWith(HttpStatusCode.UNAUTHORIZED_401, OAUTH2_INVALID_ACCESS_TOKEN_KEY, OAUTH2_UNAUTHORIZED_MESSAGE);
    }

    @Test
    void shouldInterruptWith503WhenIntrospectionFailsWithException() {
        final String token = prepareToken();
        prepareOauth2Resource();

        when(ctx.interruptWith(any(ExecutionFailure.class))).thenReturn(Completable.error(new RuntimeException(MOCK_EXCEPTION)));

        final OAuth2Response oAuth2Response = mock(OAuth2Response.class);
        when(oAuth2Response.isSuccess()).thenReturn(false);
        when(oAuth2Response.getThrowable()).thenReturn(new RuntimeException(MOCK_INTROSPECT_EXCEPTION));

        doAnswer(i -> {
                i.<Handler<OAuth2Response>>getArgument(1).handle(oAuth2Response);
                return null;
            })
            .when(oAuth2Resource)
            .introspect(eq(token), any(Handler.class));

        final TestObserver<Void> obs = cut.onRequest(ctx).test();
        obs.assertError(Throwable.class);

        verify(ctx, never()).setAttribute(eq(Oauth2Policy.CONTEXT_ATTRIBUTE_CLIENT_ID), anyString());
        verify(responseHeaders).add(eq(HttpHeaderNames.WWW_AUTHENTICATE), anyString());

        verifyInterruptWith(HttpStatusCode.SERVICE_UNAVAILABLE_503, OAUTH2_SERVER_UNAVAILABLE_KEY, OAUTH2_TEMPORARILY_UNAVAILABLE_MESSAGE);
    }

    @Test
    void shouldInterruptWith401WhenGoodIntrospectionWithInvalidPayload() {
        final String token = prepareToken();
        prepareOauth2Resource();

        when(ctx.interruptWith(any(ExecutionFailure.class))).thenReturn(Completable.error(new RuntimeException(MOCK_EXCEPTION)));

        prepareIntrospection(token, INVALID_PAYLOAD, true);

        final TestObserver<Void> obs = cut.onRequest(ctx).test();
        obs.assertError(Throwable.class);

        verify(ctx, never()).setAttribute(eq(Oauth2Policy.CONTEXT_ATTRIBUTE_CLIENT_ID), anyString());
        verify(responseHeaders).add(eq(HttpHeaderNames.WWW_AUTHENTICATE), anyString());

        verifyInterruptWith(HttpStatusCode.UNAUTHORIZED_401, OAUTH2_INVALID_SERVER_RESPONSE_KEY, OAUTH2_UNAUTHORIZED_MESSAGE);
    }

    @Test
    void shouldCompleteWhenGoodIntrospectionWithoutClientId() throws IOException {
        final String token = prepareToken();
        prepareOauth2Resource();

        prepareIntrospection(token, readResource("/io/gravitee/policy/oauth2/oauth2-response03.json"), true);

        final TestObserver<Void> obs = cut.onRequest(ctx).test();
        obs.assertComplete();

        verify(ctx, never()).setAttribute(eq(Oauth2Policy.CONTEXT_ATTRIBUTE_CLIENT_ID), anyString());
        verify(ctx).setAttribute(ATTR_USER_ROLES, List.of("read", "write", "admin"));
    }

    @Test
    void shouldCompleteWhenGoodIntrospectionWithClientId() throws IOException {
        final String token = prepareToken();
        prepareOauth2Resource();

        prepareIntrospection(token, readResource("/io/gravitee/policy/oauth2/oauth2-response04.json"), true);

        final TestObserver<Void> obs = cut.onRequest(ctx).test();
        obs.assertComplete();

        verify(ctx).setAttribute(Oauth2Policy.CONTEXT_ATTRIBUTE_CLIENT_ID, "my-client-id");
        verify(ctx).setAttribute(ATTR_USER_ROLES, List.of("read", "write", "admin"));
    }

    @Test
    void shouldCompleteWhenGoodIntrospectionWithClientIdUsingScpKey() throws IOException {
        final String token = prepareToken();
        prepareOauth2Resource();

        prepareIntrospection(token, readResource("/io/gravitee/policy/oauth2/oauth2-response10.json"), true);

        final TestObserver<Void> obs = cut.onRequest(ctx).test();
        obs.assertComplete();

        verify(ctx).setAttribute(Oauth2Policy.CONTEXT_ATTRIBUTE_CLIENT_ID, "my-client-id");
        verify(ctx).setAttribute(ATTR_USER_ROLES, List.of("read", "write", "admin"));
    }

    @Test
    void shouldCompleteWithUser() throws IOException {
        final String user = "my-user";
        final String token = prepareToken();
        prepareOauth2Resource();

        final String payload = readJsonResource("/io/gravitee/policy/oauth2/oauth2-response03.json").put("sub", user).toString();
        prepareIntrospection(token, payload, true);

        final Metrics metrics = mock(Metrics.class);
        when(ctx.metrics()).thenReturn(metrics);

        final TestObserver<Void> obs = cut.onRequest(ctx).test();
        obs.assertComplete();

        verify(ctx).setAttribute(ATTR_USER, user);
        verify(metrics).setUser(user);
    }

    @Test
    void shouldCompleteWithExtractPayload() throws IOException {
        final String token = prepareToken();
        prepareOauth2Resource();

        final String payload = readResource("/io/gravitee/policy/oauth2/oauth2-response03.json");
        prepareIntrospection(token, payload, true);

        when(configuration.isExtractPayload()).thenReturn(true);

        final TestObserver<Void> obs = cut.onRequest(ctx).test();
        obs.assertComplete();

        verify(ctx).setAttribute(CONTEXT_ATTRIBUTE_OAUTH_PAYLOAD, payload);
    }

    @Test
    void shouldCompleteWhenRequiredScopesPresent() throws IOException {
        final String token = prepareToken();
        prepareOauth2Resource();

        when(configuration.isCheckRequiredScopes()).thenReturn(true);
        when(configuration.getRequiredScopes()).thenReturn(List.of("write", "admin"));

        prepareIntrospection(token, readResource("/io/gravitee/policy/oauth2/oauth2-response04.json"), true);

        final TestObserver<Void> obs = cut.onRequest(ctx).test();
        obs.assertComplete();

        verify(ctx).setAttribute(Oauth2Policy.CONTEXT_ATTRIBUTE_CLIENT_ID, "my-client-id");
        verify(ctx).setAttribute(ATTR_USER_ROLES, List.of("read", "write", "admin"));
    }

    @Test
    void shouldInterruptWith401WhenRequiredScopesAbsentStrictMode() throws IOException {
        final String token = prepareToken();
        prepareOauth2Resource();

        when(ctx.interruptWith(any(ExecutionFailure.class))).thenReturn(Completable.error(new RuntimeException(MOCK_EXCEPTION)));

        when(configuration.isCheckRequiredScopes()).thenReturn(true);
        when(configuration.isModeStrict()).thenReturn(true);
        when(configuration.getRequiredScopes()).thenReturn(List.of("other", "admin"));

        prepareIntrospection(token, readResource("/io/gravitee/policy/oauth2/oauth2-response04.json"), true);

        final TestObserver<Void> obs = cut.onRequest(ctx).test();
        obs.assertError(Throwable.class);

        verify(ctx).setAttribute(Oauth2Policy.CONTEXT_ATTRIBUTE_CLIENT_ID, "my-client-id");
        verify(ctx).setAttribute(ATTR_USER_ROLES, List.of("read", "write", "admin"));

        verifyInterruptWith(HttpStatusCode.UNAUTHORIZED_401, OAUTH2_INSUFFICIENT_SCOPE_KEY, OAUTH2_UNAUTHORIZED_MESSAGE);
    }

    @Test
    void shouldInterruptWith401WhenRequiredScopesPartiallyPresentNonStrictMode() throws IOException {
        final String token = prepareToken();
        prepareOauth2Resource();

        when(configuration.isCheckRequiredScopes()).thenReturn(true);
        when(configuration.isModeStrict()).thenReturn(false);
        when(configuration.getRequiredScopes()).thenReturn(List.of("other", "admin"));

        prepareIntrospection(token, readResource("/io/gravitee/policy/oauth2/oauth2-response04.json"), true);

        final TestObserver<Void> obs = cut.onRequest(ctx).test();
        obs.assertComplete();

        verify(ctx).setAttribute(Oauth2Policy.CONTEXT_ATTRIBUTE_CLIENT_ID, "my-client-id");
        verify(ctx).setAttribute(ATTR_USER_ROLES, List.of("read", "write", "admin"));
    }

    @Test
    void shouldPutIntrospectionToCache() throws IOException {
        final String token = prepareToken();
        prepareOauth2Resource();
        prepareCacheResource();

        final String payload = readResource("/io/gravitee/policy/oauth2/oauth2-response04.json");
        prepareIntrospection(token, payload, true);

        final TestObserver<Void> obs = cut.onRequest(ctx).test();
        obs.assertComplete();

        verify(ctx).setAttribute(Oauth2Policy.CONTEXT_ATTRIBUTE_CLIENT_ID, "my-client-id");
        verify(cache)
            .put(
                argThat(e -> {
                    assertEquals(token, e.key());
                    assertEquals(payload, e.value());
                    return true;
                })
            );
    }

    private void prepareCacheResource() {
        when(configuration.getOauthCacheResource()).thenReturn(OAUTH_CACHE_RESOURCE);
        when(cacheResource.getCache(any(BaseExecutionContext.class))).thenReturn(cache);
        when(resourceManager.getResource(OAUTH_CACHE_RESOURCE, CacheResource.class)).thenReturn(cacheResource);
    }

    @Test
    void shouldPutIntrospectionToCacheWithExpiration() throws IOException {
        final String token = prepareToken();
        prepareOauth2Resource();
        prepareCacheResource();

        final String payload = readJsonResource("/io/gravitee/policy/oauth2/oauth2-response04.json")
            .put("exp", (System.currentTimeMillis() + 3600000) / 1000)
            .toString();
        prepareIntrospection(token, payload, true);

        final TestObserver<Void> obs = cut.onRequest(ctx).test();
        obs.assertComplete();

        verify(ctx).setAttribute(Oauth2Policy.CONTEXT_ATTRIBUTE_CLIENT_ID, "my-client-id");
        verify(cache)
            .put(
                argThat(e -> {
                    assertEquals(token, e.key());
                    assertEquals(payload, e.value());
                    assertTrue(e.timeToLive() > 0);
                    return true;
                })
            );
    }

    @Test
    void shouldGetIntrospectionFromCache() throws IOException {
        final String token = prepareToken();
        prepareOauth2Resource();
        prepareCacheResource();

        final String payload = readResource("/io/gravitee/policy/oauth2/oauth2-response04.json");
        final CacheElement cacheElement = new CacheElement(token, payload);

        when(cache.get(token)).thenReturn(cacheElement);

        final TestObserver<Void> obs = cut.onRequest(ctx).test();
        obs.assertComplete();

        verify(ctx).setAttribute(Oauth2Policy.CONTEXT_ATTRIBUTE_CLIENT_ID, "my-client-id");
    }

    @Test
    void shouldReturnOrder100() {
        assertEquals(100, cut.order());
    }

    @Test
    void shouldReturnOAuth2PolicyId() {
        assertEquals("oauth2", cut.id());
    }

    @Test
    void shouldValidateSubscription() {
        assertTrue(cut.requireSubscription());
    }

    @Test
    void extractSecurityTokenShouldReturnEmptyWhenNoOauth2Resource() {
        final TestObserver<SecurityToken> obs = cut.extractSecurityToken(ctx).test();

        obs.assertComplete().assertValueCount(0);
        verify(ctx, times(0)).setAttribute(eq(CONTEXT_ATTRIBUTE_JWT), any());
    }

    @Test
    void extractSecurityTokenShouldReturnEmptyWhenTokenIsAbsent() {
        prepareOauth2Resource();

        final TestObserver<SecurityToken> obs = cut.extractSecurityToken(ctx).test();

        obs.assertComplete().assertValueCount(0);
        verify(ctx, times(0)).setAttribute(eq(CONTEXT_ATTRIBUTE_JWT), any());
    }

    @Test
    void extractSecurityTokenShouldReturnInvalidWhenTokenIsPresentButIntrospectionFails() {
        prepareOauth2Resource();
        String token = prepareToken();
        prepareIntrospection(token, null, false);

        final TestObserver<SecurityToken> obs = cut.extractSecurityToken(ctx).test();

        obs.assertComplete().assertValueCount(1);
        obs.assertValue(securityToken ->
            securityToken.getTokenType().equals(SecurityToken.TokenType.CLIENT_ID.name()) && securityToken.isInvalid()
        );
    }

    @Test
    void extractSecurityTokenShouldReturnInvalidWhenIntrospectionInError() {
        prepareOauth2Resource();
        String token = prepareToken();
        OAuth2ResourceException errorDuringIntrospection = new OAuth2ResourceException("Error during introspection");
        prepareIntrospection(token, errorDuringIntrospection);

        final TestObserver<SecurityToken> obs = cut.extractSecurityToken(ctx).test();

        obs.assertError(errorDuringIntrospection);
    }

    @Test
    void extractSecurityTokenShouldReturnTokenWhenTokenIsPresentAndIntrospectionSucceed() throws IOException {
        prepareOauth2Resource();
        String token = prepareToken();
        final String payload = readResource("/io/gravitee/policy/oauth2/oauth2-response09.json");
        prepareIntrospection(token, payload, true);

        final TestObserver<SecurityToken> obs = cut.extractSecurityToken(ctx).test();

        obs.assertComplete().assertValueCount(1);
        obs.assertValue(securityToken ->
            securityToken.getTokenType().equals(SecurityToken.TokenType.CLIENT_ID.name()) &&
            securityToken.getTokenValue().equals("my-test-client-id")
        );
        verify(ctx).setAttribute(eq(CONTEXT_ATTRIBUTE_JWT), Mockito.<LazyJWT>argThat(jwt -> token.equals(jwt.getToken())));
    }

    @Test
    void shouldIntrospectOnlyOnce() throws IOException {
        String token = "my-test-token";

        final String payload = readJsonResource("/io/gravitee/policy/oauth2/oauth2-response09.json").toString();
        prepareIntrospection(token, payload, true);

        HttpPlainExecutionContext ctx = new DefaultExecutionContext(mock(MutableRequest.class), mock(MutableResponse.class));
        TestObserver<TokenIntrospectionResult> result1 = cut.introspectAccessToken(ctx, token, oAuth2Resource).test();
        TestObserver<TokenIntrospectionResult> result2 = cut.introspectAccessToken(ctx, token, oAuth2Resource).test();

        result1.assertComplete().assertValueCount(1);
        result2.assertComplete().assertValueCount(1);

        // ensure introspection as been made only once
        verify(oAuth2Resource, times(1)).introspect(any(), any());
    }

    private String prepareToken() {
        final String token = UUID.randomUUID().toString();
        when(headers.getAll(AUTHORIZATION)).thenReturn(List.of("Bearer" + token));
        lenient().when(ctx.getAttribute(CONTEXT_ATTRIBUTE_OAUTH_ACCESS_TOKEN)).thenReturn(token);

        return token;
    }

    private void prepareOauth2Resource() {
        when(configuration.getOauthResource()).thenReturn(OAUTH_RESOURCE);
        when(templateEngine.getValue(OAUTH_RESOURCE, String.class)).thenReturn(OAUTH_RESOURCE);
        when(resourceManager.getResource(OAUTH_RESOURCE, OAuth2Resource.class)).thenReturn(oAuth2Resource);
        lenient().when(oAuth2Resource.getScopeSeparator()).thenReturn(DEFAULT_OAUTH_SCOPE_SEPARATOR);
    }

    private void prepareIntrospection(String token, String payload, boolean success) {
        final OAuth2Response oAuth2Response = mock(OAuth2Response.class);
        lenient().when(oAuth2Response.isSuccess()).thenReturn(success);
        lenient().when(oAuth2Response.getPayload()).thenReturn(payload);

        doAnswer(i -> {
                i.<Handler<OAuth2Response>>getArgument(1).handle(oAuth2Response);
                return null;
            })
            .when(oAuth2Resource)
            .introspect(eq(token), any(Handler.class));
    }

    private void prepareIntrospection(String token, Throwable throwable) {
        final OAuth2Response oAuth2Response = mock(OAuth2Response.class);
        lenient().when(oAuth2Response.isSuccess()).thenReturn(false);
        lenient().when(oAuth2Response.getPayload()).thenReturn(throwable.getMessage());
        lenient().when(oAuth2Response.getThrowable()).thenReturn(throwable);

        doAnswer(i -> {
                i.<Handler<OAuth2Response>>getArgument(1).handle(oAuth2Response);
                return null;
            })
            .when(oAuth2Resource)
            .introspect(eq(token), any(Handler.class));
    }

    private void verifyInterruptWith(int httpStatus, String key, final String message) {
        verify(ctx)
            .interruptWith(
                argThat(failure -> {
                    assertEquals(httpStatus, failure.statusCode());
                    assertEquals(message, failure.message());
                    assertEquals(key, failure.key());
                    assertNull(failure.parameters());
                    return true;
                })
            );
    }

    private ObjectNode readJsonResource(String resource) throws IOException {
        return (ObjectNode) MAPPER.readTree(this.getClass().getResourceAsStream(resource));
    }

    private String readResource(String resource) throws IOException {
        InputStream stream = this.getClass().getResourceAsStream(resource);
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int length;
        while ((length = stream.read(buffer)) != -1) {
            result.write(buffer, 0, length);
        }
        return result.toString(StandardCharsets.UTF_8.name());
    }
}
