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
package io.gravitee.policy.v3.oauth2;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.argThat;

import com.fasterxml.jackson.databind.JsonNode;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.handler.Handler;
import io.gravitee.gateway.api.http.HttpHeaderNames;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.oauth2.configuration.OAuth2PolicyConfiguration;
import io.gravitee.resource.api.ResourceConfiguration;
import io.gravitee.resource.api.ResourceManager;
import io.gravitee.resource.cache.api.Cache;
import io.gravitee.resource.cache.api.CacheResource;
import io.gravitee.resource.cache.api.Element;
import io.gravitee.resource.oauth2.api.OAuth2Resource;
import io.gravitee.resource.oauth2.api.OAuth2Response;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatcher;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
@ExtendWith(MockitoExtension.class)
class Oauth2PolicyV3Test {

    @Mock
    Request mockRequest;

    @Mock
    Response mockResponse;

    @Mock
    ExecutionContext mockExecutionContext;

    @Mock
    PolicyChain mockPolicychain;

    @Mock
    ResourceManager resourceManager;

    @Mock
    OAuth2Resource customOAuth2Resource;

    @Mock
    ResourceConfiguration oauth2ResourceConfiguration;

    @Mock
    OAuth2PolicyConfiguration oAuth2PolicyConfiguration;

    @Mock
    TemplateEngine templateEngine;

    @Mock
    CacheResource customCacheResource;

    private static final String DEFAULT_OAUTH_SCOPE_SEPARATOR = " ";

    @Test
    void shouldFailedIfNoOAuthResourceProvided() {
        Oauth2PolicyV3 policy = new Oauth2PolicyV3(oAuth2PolicyConfiguration);

        when(mockExecutionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(oAuth2PolicyConfiguration.getOauthResource()).thenReturn("oauth2");
        when(mockExecutionContext.getTemplateEngine()).thenReturn(templateEngine);

        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(mockPolicychain)
            .failWith(
                argThat(result ->
                    result.statusCode() == HttpStatusCode.UNAUTHORIZED_401 && Oauth2PolicyV3.OAUTH2_MISSING_SERVER_KEY.equals(result.key())
                )
            );
    }

    @Test
    void shouldFailedIfNoAuthorizationHeaderProvided() {
        Oauth2PolicyV3 policy = new Oauth2PolicyV3(oAuth2PolicyConfiguration);

        when(mockRequest.headers()).thenReturn(HttpHeaders.create());
        when(mockExecutionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(oAuth2PolicyConfiguration.getOauthResource()).thenReturn("oauth2");
        when(resourceManager.getResource(oAuth2PolicyConfiguration.getOauthResource(), OAuth2Resource.class))
            .thenReturn(customOAuth2Resource);
        when(mockResponse.headers()).thenReturn(HttpHeaders.create());
        when(mockExecutionContext.getTemplateEngine()).thenReturn(templateEngine);

        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(mockPolicychain)
            .failWith(
                argThat(result ->
                    result.statusCode() == HttpStatusCode.UNAUTHORIZED_401 && Oauth2PolicyV3.OAUTH2_MISSING_HEADER_KEY.equals(result.key())
                )
            );
    }

    @Test
    void shouldFailedIfNoAuthorizationHeaderBearerProvided() {
        final HttpHeaders headers = HttpHeaders.create().set("Authorization", "Basic Test");

        Oauth2PolicyV3 policy = new Oauth2PolicyV3(oAuth2PolicyConfiguration);

        when(mockExecutionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(oAuth2PolicyConfiguration.getOauthResource()).thenReturn("oauth2");
        when(resourceManager.getResource(oAuth2PolicyConfiguration.getOauthResource(), OAuth2Resource.class))
            .thenReturn(customOAuth2Resource);
        when(mockRequest.headers()).thenReturn(headers);
        when(mockResponse.headers()).thenReturn(HttpHeaders.create());
        when(mockExecutionContext.getTemplateEngine()).thenReturn(templateEngine);

        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(mockPolicychain)
            .failWith(
                argThat(result ->
                    result.statusCode() == HttpStatusCode.UNAUTHORIZED_401 && Oauth2PolicyV3.OAUTH2_MISSING_HEADER_KEY.equals(result.key())
                )
            );
    }

    @Test
    void shouldFailedIfNoAuthorizationAccessTokenBearerIsEmptyProvided() {
        HttpHeaders headers = HttpHeaders.create().set("Authorization", "Bearer");

        Oauth2PolicyV3 policy = new Oauth2PolicyV3(oAuth2PolicyConfiguration);

        when(mockExecutionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(oAuth2PolicyConfiguration.getOauthResource()).thenReturn("oauth2");
        when(resourceManager.getResource(oAuth2PolicyConfiguration.getOauthResource(), OAuth2Resource.class))
            .thenReturn(customOAuth2Resource);
        when(mockRequest.headers()).thenReturn(headers);
        when(mockResponse.headers()).thenReturn(HttpHeaders.create());
        when(mockExecutionContext.getTemplateEngine()).thenReturn(templateEngine);

        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(mockPolicychain)
            .failWith(
                argThat(result ->
                    result.statusCode() == HttpStatusCode.UNAUTHORIZED_401 &&
                    Oauth2PolicyV3.OAUTH2_MISSING_ACCESS_TOKEN_KEY.equals(result.key())
                )
            );
    }

    @Test
    void shouldCallOAuthResource() throws Exception {
        String bearer = UUID.randomUUID().toString();

        final HttpHeaders headers = HttpHeaders.create().set("Authorization", "Bearer " + bearer);

        Oauth2PolicyV3 policy = new Oauth2PolicyV3(oAuth2PolicyConfiguration);
        when(mockRequest.headers()).thenReturn(headers);
        when(mockExecutionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(oAuth2PolicyConfiguration.getOauthResource()).thenReturn("oauth2");
        when(resourceManager.getResource(oAuth2PolicyConfiguration.getOauthResource(), OAuth2Resource.class))
            .thenReturn(customOAuth2Resource);
        when(mockExecutionContext.getTemplateEngine()).thenReturn(templateEngine);

        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(customOAuth2Resource).introspect(eq(bearer), any(Handler.class));
        verify(mockExecutionContext).setAttribute(eq(Oauth2PolicyV3.CONTEXT_ATTRIBUTE_OAUTH_ACCESS_TOKEN), eq(bearer));
    }

    @Test
    void shouldCallCacheResource() throws Exception {
        String bearer = UUID.randomUUID().toString();

        final HttpHeaders headers = HttpHeaders.create().set("Authorization", "Bearer " + bearer);

        Oauth2PolicyV3 policy = new Oauth2PolicyV3(oAuth2PolicyConfiguration);
        when(mockRequest.headers()).thenReturn(headers);
        when(mockExecutionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(oAuth2PolicyConfiguration.getOauthResource()).thenReturn("oauth2");
        when(resourceManager.getResource(oAuth2PolicyConfiguration.getOauthResource(), OAuth2Resource.class))
            .thenReturn(customOAuth2Resource);
        when(oAuth2PolicyConfiguration.getOauthCacheResource()).thenReturn("cache");
        when(resourceManager.getResource(oAuth2PolicyConfiguration.getOauthCacheResource(), CacheResource.class))
            .thenReturn(customCacheResource);
        Element cacheElement = mock(Element.class);
        JsonNode jsonNode = readJsonResource("/io/gravitee/policy/oauth2/oauth2-response07.json");
        when(cacheElement.value()).thenReturn(jsonNode.toPrettyString());
        Cache cache = mock(Cache.class);
        when(cache.get(eq(bearer))).thenReturn(cacheElement);
        when(customCacheResource.getCache(any(ExecutionContext.class))).thenReturn(cache);

        when(mockExecutionContext.getTemplateEngine()).thenReturn(templateEngine);

        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(customOAuth2Resource, times(0)).introspect(eq(bearer), any(Handler.class));
        verify(mockExecutionContext).setAttribute(eq(Oauth2PolicyV3.CONTEXT_ATTRIBUTE_OAUTH_ACCESS_TOKEN), eq(bearer));
    }

    @Test
    void shouldCallOAuthResourceAndHandleResult() throws Exception {
        String bearer = UUID.randomUUID().toString();

        final HttpHeaders headers = HttpHeaders.create().set("Authorization", "Bearer " + bearer);

        Oauth2PolicyV3 policy = new Oauth2PolicyV3(oAuth2PolicyConfiguration);
        when(mockRequest.headers()).thenReturn(headers);
        when(mockExecutionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(oAuth2PolicyConfiguration.getOauthResource()).thenReturn("oauth2");
        when(resourceManager.getResource(oAuth2PolicyConfiguration.getOauthResource(), OAuth2Resource.class))
            .thenReturn(customOAuth2Resource);
        when(mockExecutionContext.getTemplateEngine()).thenReturn(templateEngine);

        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(customOAuth2Resource).introspect(eq(bearer), any(Handler.class));
        verify(mockExecutionContext).setAttribute(eq(Oauth2PolicyV3.CONTEXT_ATTRIBUTE_OAUTH_ACCESS_TOKEN), eq(bearer));
    }

    @Test
    void shouldValidScopes_noRequiredScopes() throws IOException {
        JsonNode jsonNode = readJsonResource("/io/gravitee/policy/oauth2/oauth2-response01.json");
        Collection<String> scopes = Oauth2PolicyV3.extractScopes(jsonNode, DEFAULT_OAUTH_SCOPE_SEPARATOR);
        boolean valid = Oauth2PolicyV3.hasRequiredScopes(scopes, null, false);
        Assertions.assertTrue(valid);
    }

    @Test
    void shouldNotValidScopes_emptyOAuthResponse() throws IOException {
        JsonNode jsonNode = readJsonResource("/io/gravitee/policy/oauth2/oauth2-response01.json");
        Collection<String> scopes = Oauth2PolicyV3.extractScopes(jsonNode, DEFAULT_OAUTH_SCOPE_SEPARATOR);
        boolean valid = Oauth2PolicyV3.hasRequiredScopes(scopes, Collections.singletonList("read"), false);
        Assertions.assertFalse(valid);
    }

    @Test
    void shouldValidScopes_emptyOAuthResponse() throws IOException {
        JsonNode jsonNode = readJsonResource("/io/gravitee/policy/oauth2/oauth2-response02.json");
        Collection<String> scopes = Oauth2PolicyV3.extractScopes(jsonNode, DEFAULT_OAUTH_SCOPE_SEPARATOR);
        boolean valid = Oauth2PolicyV3.hasRequiredScopes(scopes, Collections.singletonList("read"), false);
        Assertions.assertTrue(valid);
    }

    @Test
    void shouldValidScopes_stringOfScopes() throws IOException {
        JsonNode jsonNode = readJsonResource("/io/gravitee/policy/oauth2/oauth2-response04.json");
        Collection<String> scopes = Oauth2PolicyV3.extractScopes(jsonNode, DEFAULT_OAUTH_SCOPE_SEPARATOR);
        boolean valid = Oauth2PolicyV3.hasRequiredScopes(scopes, Collections.singletonList("read"), false);
        Assertions.assertTrue(valid);
    }

    @Test
    void shouldValidScopes_stringOfScopes_moreOauthScope() throws IOException {
        JsonNode jsonNode = readJsonResource("/io/gravitee/policy/oauth2/oauth2-response08.json");
        Collection<String> scopes = Oauth2PolicyV3.extractScopes(jsonNode, DEFAULT_OAUTH_SCOPE_SEPARATOR);
        boolean valid = Oauth2PolicyV3.hasRequiredScopes(scopes, Arrays.asList("read", "functional-settings"), true);
        Assertions.assertTrue(valid);
    }

    @Test
    void shouldValidScopes_stringOfScopes_customSeparator() throws IOException {
        JsonNode jsonNode = readJsonResource("/io/gravitee/policy/oauth2/oauth2-response06.json");
        Collection<String> scopes = Oauth2PolicyV3.extractScopes(jsonNode, ",");
        boolean valid = Oauth2PolicyV3.hasRequiredScopes(scopes, Collections.singletonList("read"), false);
        Assertions.assertTrue(valid);
    }

    @Test
    void shouldValidScopes_arrayOfScope() throws IOException {
        JsonNode jsonNode = readJsonResource("/io/gravitee/policy/oauth2/oauth2-response05.json");
        Collection<String> scopes = Oauth2PolicyV3.extractScopes(jsonNode, DEFAULT_OAUTH_SCOPE_SEPARATOR);
        boolean valid = Oauth2PolicyV3.hasRequiredScopes(scopes, Collections.singletonList("read"), false);
        Assertions.assertTrue(valid);
    }

    @Test
    void shouldValidScopes_arrayOfScopes() throws IOException {
        JsonNode jsonNode = readJsonResource("/io/gravitee/policy/oauth2/oauth2-response07.json");
        Collection<String> scopes = Oauth2PolicyV3.extractScopes(jsonNode, DEFAULT_OAUTH_SCOPE_SEPARATOR);
        boolean valid = Oauth2PolicyV3.hasRequiredScopes(scopes, Arrays.asList("read", "write"), false);
        Assertions.assertTrue(valid);
    }

    @Test
    void shouldValidScopes_arrayOfScopes_strict() throws IOException {
        JsonNode jsonNode = readJsonResource("/io/gravitee/policy/oauth2/oauth2-response05.json");
        Collection<String> scopes = Oauth2PolicyV3.extractScopes(jsonNode, DEFAULT_OAUTH_SCOPE_SEPARATOR);
        boolean valid = Oauth2PolicyV3.hasRequiredScopes(scopes, Arrays.asList("read", "write", "admin"), true);
        Assertions.assertTrue(valid);
    }

    @Test
    void shoulValidScopes_arrayOfScope_strict() throws IOException {
        JsonNode jsonNode = readJsonResource("/io/gravitee/policy/oauth2/oauth2-response05.json");
        Collection<String> scopes = Oauth2PolicyV3.extractScopes(jsonNode, DEFAULT_OAUTH_SCOPE_SEPARATOR);
        boolean valid = Oauth2PolicyV3.hasRequiredScopes(scopes, Collections.singletonList("read"), true);
        Assertions.assertTrue(valid);
    }

    @Test
    void shouldValidScopes_arrayOfScopes_strict2() throws IOException {
        JsonNode jsonNode = readJsonResource("/io/gravitee/policy/oauth2/oauth2-response05.json");
        Collection<String> scopes = Oauth2PolicyV3.extractScopes(jsonNode, DEFAULT_OAUTH_SCOPE_SEPARATOR);
        boolean valid = Oauth2PolicyV3.hasRequiredScopes(scopes, Arrays.asList("read", "write"), true);
        Assertions.assertTrue(valid);
    }

    @Test
    void shouldFail_badIntrospection() throws IOException {
        HttpHeaders httpHeaders = mock(HttpHeaders.class);
        when(mockResponse.headers()).thenReturn(httpHeaders);

        Oauth2PolicyV3 policy = new Oauth2PolicyV3(oAuth2PolicyConfiguration);
        Handler<OAuth2Response> handler = policy.handleResponse(mockPolicychain, mockRequest, mockResponse, mockExecutionContext, null);

        String payload = readResource("/io/gravitee/policy/oauth2/oauth2-response03.json");
        handler.handle(new OAuth2Response(false, payload));

        verify(mockExecutionContext, never()).setAttribute(eq(Oauth2PolicyV3.CONTEXT_ATTRIBUTE_CLIENT_ID), anyString());
        verify(httpHeaders).add(eq(HttpHeaderNames.WWW_AUTHENTICATE), anyString());

        verify(mockPolicychain)
            .failWith(
                argThat(result ->
                    result.statusCode() == HttpStatusCode.UNAUTHORIZED_401 &&
                    Oauth2PolicyV3.OAUTH2_INVALID_ACCESS_TOKEN_KEY.equals(result.key())
                )
            );
    }

    @Test
    void shouldFail_exception() throws IOException {
        HttpHeaders httpHeaders = mock(HttpHeaders.class);
        when(mockResponse.headers()).thenReturn(httpHeaders);

        Oauth2PolicyV3 policy = new Oauth2PolicyV3(oAuth2PolicyConfiguration);
        Handler<OAuth2Response> handler = policy.handleResponse(mockPolicychain, mockRequest, mockResponse, mockExecutionContext, null);

        handler.handle(new OAuth2Response(new Exception()));

        verify(mockExecutionContext, never()).setAttribute(eq(Oauth2PolicyV3.CONTEXT_ATTRIBUTE_CLIENT_ID), anyString());
        verify(httpHeaders).add(eq(HttpHeaderNames.WWW_AUTHENTICATE), anyString());

        verify(mockPolicychain)
            .failWith(
                argThat(result ->
                    result.statusCode() == HttpStatusCode.SERVICE_UNAVAILABLE_503 &&
                    Oauth2PolicyV3.OAUTH2_SERVER_UNAVAILABLE_KEY.equals(result.key())
                )
            );
    }

    @Test
    void shouldFail_invalidResponseFormat() throws IOException {
        HttpHeaders httpHeaders = mock(HttpHeaders.class);
        when(mockResponse.headers()).thenReturn(httpHeaders);

        Oauth2PolicyV3 policy = new Oauth2PolicyV3(oAuth2PolicyConfiguration);
        Handler<OAuth2Response> handler = policy.handleResponse(mockPolicychain, mockRequest, mockResponse, mockExecutionContext, null);

        handler.handle(new OAuth2Response(true, "blablabla"));

        verify(mockExecutionContext, never()).setAttribute(eq(Oauth2PolicyV3.CONTEXT_ATTRIBUTE_CLIENT_ID), anyString());
        verify(httpHeaders).add(eq(HttpHeaderNames.WWW_AUTHENTICATE), anyString());

        verify(mockPolicychain)
            .failWith(
                argThat(result ->
                    result.statusCode() == HttpStatusCode.UNAUTHORIZED_401 &&
                    Oauth2PolicyV3.OAUTH2_INVALID_SERVER_RESPONSE_KEY.equals(result.key())
                )
            );
    }

    @Test
    void shouldFail_goodIntrospection_noClientId() throws IOException {
        HttpHeaders httpHeaders = mock(HttpHeaders.class);

        Oauth2PolicyV3 policy = new Oauth2PolicyV3(oAuth2PolicyConfiguration);
        when(oAuth2PolicyConfiguration.getOauthResource()).thenReturn("oauth2");
        when(mockExecutionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(resourceManager.getResource(oAuth2PolicyConfiguration.getOauthResource(), OAuth2Resource.class))
            .thenReturn(customOAuth2Resource);
        when(customOAuth2Resource.getScopeSeparator()).thenReturn(DEFAULT_OAUTH_SCOPE_SEPARATOR);
        Handler<OAuth2Response> handler = policy.handleResponse(mockPolicychain, mockRequest, mockResponse, mockExecutionContext, null);

        String payload = readResource("/io/gravitee/policy/oauth2/oauth2-response03.json");
        handler.handle(new OAuth2Response(true, payload));

        verify(mockExecutionContext, never()).setAttribute(eq(Oauth2PolicyV3.CONTEXT_ATTRIBUTE_CLIENT_ID), anyString());
        verify(httpHeaders, never()).add(eq(HttpHeaderNames.WWW_AUTHENTICATE), anyString());
        verify(mockPolicychain).doNext(mockRequest, mockResponse);
    }

    @Test
    void shouldValidate_goodIntrospection_withClientId() throws IOException {
        when(oAuth2PolicyConfiguration.isExtractPayload()).thenReturn(true);

        Oauth2PolicyV3 policy = new Oauth2PolicyV3(oAuth2PolicyConfiguration);
        when(mockExecutionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(resourceManager.getResource(oAuth2PolicyConfiguration.getOauthResource(), OAuth2Resource.class))
            .thenReturn(customOAuth2Resource);
        when(customOAuth2Resource.getScopeSeparator()).thenReturn(DEFAULT_OAUTH_SCOPE_SEPARATOR);

        Handler<OAuth2Response> handler = policy.handleResponse(mockPolicychain, mockRequest, mockResponse, mockExecutionContext, null);

        String payload = readResource("/io/gravitee/policy/oauth2/oauth2-response04.json");
        handler.handle(new OAuth2Response(true, payload));

        verify(mockExecutionContext).setAttribute(Oauth2PolicyV3.CONTEXT_ATTRIBUTE_CLIENT_ID, "my-client-id");
        verify(mockExecutionContext).setAttribute(Oauth2PolicyV3.CONTEXT_ATTRIBUTE_OAUTH_PAYLOAD, payload);
        verify(mockExecutionContext)
            .setAttribute(
                eq(ExecutionContext.ATTR_USER_ROLES),
                argThat(
                    new ArgumentMatcher<List<String>>() {
                        @Override
                        public boolean matches(List<String> scopes) {
                            return scopes.get(0).equals("read") && scopes.get(1).equals("write") && scopes.get(2).equals("admin");
                        }
                    }
                )
            );
        verify(mockPolicychain).doNext(mockRequest, mockResponse);
    }

    @Test
    void shouldValidate_goodIntrospection_withClientId_validScopes() throws IOException {
        when(oAuth2PolicyConfiguration.isCheckRequiredScopes()).thenReturn(true);
        when(mockExecutionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(resourceManager.getResource(oAuth2PolicyConfiguration.getOauthResource(), OAuth2Resource.class))
            .thenReturn(customOAuth2Resource);
        when(customOAuth2Resource.getScopeSeparator()).thenReturn(DEFAULT_OAUTH_SCOPE_SEPARATOR);

        Oauth2PolicyV3 policy = new Oauth2PolicyV3(oAuth2PolicyConfiguration);
        Handler<OAuth2Response> handler = policy.handleResponse(mockPolicychain, mockRequest, mockResponse, mockExecutionContext, null);

        String payload = readResource("/io/gravitee/policy/oauth2/oauth2-response04.json");
        handler.handle(new OAuth2Response(true, payload));

        verify(mockExecutionContext).setAttribute(Oauth2PolicyV3.CONTEXT_ATTRIBUTE_CLIENT_ID, "my-client-id");
        verify(mockPolicychain).doNext(mockRequest, mockResponse);
    }

    @Test
    void shouldValidate_goodIntrospection_withCache() throws IOException {
        when(oAuth2PolicyConfiguration.isCheckRequiredScopes()).thenReturn(true);
        when(mockExecutionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(resourceManager.getResource(oAuth2PolicyConfiguration.getOauthResource(), OAuth2Resource.class))
            .thenReturn(customOAuth2Resource);
        when(customOAuth2Resource.getScopeSeparator()).thenReturn(DEFAULT_OAUTH_SCOPE_SEPARATOR);

        Cache cache = mock(Cache.class);
        when(customCacheResource.getCache(any(ExecutionContext.class))).thenReturn(cache);

        Oauth2PolicyV3 policy = new Oauth2PolicyV3(oAuth2PolicyConfiguration);
        Handler<OAuth2Response> handler = policy.handleResponse(
            mockPolicychain,
            mockRequest,
            mockResponse,
            mockExecutionContext,
            customCacheResource
        );

        String payload = readResource("/io/gravitee/policy/oauth2/oauth2-response04.json");
        handler.handle(new OAuth2Response(true, payload));

        verify(mockExecutionContext).setAttribute(Oauth2PolicyV3.CONTEXT_ATTRIBUTE_CLIENT_ID, "my-client-id");
        verify(mockPolicychain).doNext(mockRequest, mockResponse);
        verify(cache).put(any(Element.class));
    }

    @Test
    void shouldValidate_goodIntrospection_withClientId_invalidScopes() throws IOException {
        HttpHeaders httpHeaders = mock(HttpHeaders.class);
        when(mockResponse.headers()).thenReturn(httpHeaders);
        when(oAuth2PolicyConfiguration.isCheckRequiredScopes()).thenReturn(true);
        when(oAuth2PolicyConfiguration.getRequiredScopes()).thenReturn(Collections.singletonList("super-admin"));
        when(mockExecutionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(resourceManager.getResource(oAuth2PolicyConfiguration.getOauthResource(), OAuth2Resource.class))
            .thenReturn(customOAuth2Resource);
        when(customOAuth2Resource.getScopeSeparator()).thenReturn(DEFAULT_OAUTH_SCOPE_SEPARATOR);

        Oauth2PolicyV3 policy = new Oauth2PolicyV3(oAuth2PolicyConfiguration);
        Handler<OAuth2Response> handler = policy.handleResponse(mockPolicychain, mockRequest, mockResponse, mockExecutionContext, null);

        String payload = readResource("/io/gravitee/policy/oauth2/oauth2-response04.json");
        handler.handle(new OAuth2Response(true, payload));

        verify(mockPolicychain)
            .failWith(
                argThat(result ->
                    result.statusCode() == HttpStatusCode.UNAUTHORIZED_401 &&
                    Oauth2PolicyV3.OAUTH2_INSUFFICIENT_SCOPE_KEY.equals(result.key())
                )
            );
    }

    private JsonNode readJsonResource(String resource) throws IOException {
        return Oauth2PolicyV3.MAPPER.readTree(this.getClass().getResourceAsStream(resource));
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
