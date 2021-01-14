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

import com.fasterxml.jackson.databind.JsonNode;
import io.gravitee.common.http.HttpHeaders;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.handler.Handler;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.oauth2.configuration.OAuth2PolicyConfiguration;
import io.gravitee.resource.api.ResourceConfiguration;
import io.gravitee.resource.api.ResourceManager;
import io.gravitee.resource.oauth2.api.OAuth2Resource;
import io.gravitee.resource.oauth2.api.OAuth2Response;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentMatcher;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
@RunWith(MockitoJUnitRunner.class)
public class OAuth2PolicyTest {

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

    private static final String DEFAULT_OAUTH_SCOPE_SEPARATOR = " ";

    @Test
    public void shouldFailedIfNoOAuthResourceProvided() {
        Oauth2Policy policy = new Oauth2Policy(oAuth2PolicyConfiguration);

        when(mockExecutionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(oAuth2PolicyConfiguration.getOauthResource()).thenReturn("oauth2");
        when(mockExecutionContext.getTemplateEngine()).thenReturn(templateEngine);

        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(mockPolicychain).failWith(argThat(result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401
                && Oauth2Policy.OAUTH2_MISSING_SERVER_KEY.equals(result.key())));
    }

    @Test
    public void shouldFailedIfNoAuthorizationHeaderProvided() {
        Oauth2Policy policy = new Oauth2Policy(oAuth2PolicyConfiguration);

        when(mockRequest.headers()).thenReturn(new HttpHeaders());
        when(mockExecutionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(oAuth2PolicyConfiguration.getOauthResource()).thenReturn("oauth2");
        when(resourceManager.getResource(oAuth2PolicyConfiguration.getOauthResource(), OAuth2Resource.class)).thenReturn(customOAuth2Resource);
        when(mockResponse.headers()).thenReturn(new HttpHeaders());
        when(mockExecutionContext.getTemplateEngine()).thenReturn(templateEngine);

        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(mockPolicychain).failWith(argThat(result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401
                && Oauth2Policy.OAUTH2_MISSING_HEADER_KEY.equals(result.key())));
    }

    @Test
    public void shouldFailedIfNoAuthorizationHeaderBearerProvided() {
        final HttpHeaders headers = new HttpHeaders();
        headers.setAll(new HashMap<String, String>() {
            {
                put("Authorization", "Basic Test");
            }
        });

        Oauth2Policy policy = new Oauth2Policy(oAuth2PolicyConfiguration);

        when(mockExecutionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(oAuth2PolicyConfiguration.getOauthResource()).thenReturn("oauth2");
        when(resourceManager.getResource(oAuth2PolicyConfiguration.getOauthResource(), OAuth2Resource.class)).thenReturn(customOAuth2Resource);
        when(mockRequest.headers()).thenReturn(headers);
        when(mockResponse.headers()).thenReturn(new HttpHeaders());
        when(mockExecutionContext.getTemplateEngine()).thenReturn(templateEngine);

        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(mockPolicychain).failWith(argThat(result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401
                && Oauth2Policy.OAUTH2_MISSING_HEADER_KEY.equals(result.key())));
    }

    @Test
    public void shouldFailedIfNoAuthorizationAccessTokenBearerIsEmptyProvided() {
        final HttpHeaders headers = new HttpHeaders();
        headers.setAll(new HashMap<String, String>() {
            {
                put("Authorization", "Bearer");
            }
        });

        Oauth2Policy policy = new Oauth2Policy(oAuth2PolicyConfiguration);

        when(mockExecutionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(oAuth2PolicyConfiguration.getOauthResource()).thenReturn("oauth2");
        when(resourceManager.getResource(oAuth2PolicyConfiguration.getOauthResource(), OAuth2Resource.class)).thenReturn(customOAuth2Resource);
        when(mockRequest.headers()).thenReturn(headers);
        when(mockResponse.headers()).thenReturn(new HttpHeaders());
        when(mockExecutionContext.getTemplateEngine()).thenReturn(templateEngine);

        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(mockPolicychain).failWith(argThat(result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401
                && Oauth2Policy.OAUTH2_MISSING_ACCESS_TOKEN_KEY.equals(result.key())));
    }

    @Test
    public void shouldCallOAuthResource() throws Exception {
        final HttpHeaders headers = new HttpHeaders();
        String bearer = UUID.randomUUID().toString();

        headers.setAll(new HashMap<String, String>() {
            {
                put("Authorization", "Bearer " + bearer);
            }
        });

        Oauth2Policy policy = new Oauth2Policy(oAuth2PolicyConfiguration);
        when(mockRequest.headers()).thenReturn(headers);
        when(mockExecutionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(oAuth2PolicyConfiguration.getOauthResource()).thenReturn("oauth2");
        when(resourceManager.getResource(oAuth2PolicyConfiguration.getOauthResource(), OAuth2Resource.class)).thenReturn(customOAuth2Resource);
        when(mockExecutionContext.getTemplateEngine()).thenReturn(templateEngine);

        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(customOAuth2Resource).introspect(eq(bearer), any(Handler.class));
        verify(mockExecutionContext).setAttribute(eq(Oauth2Policy.CONTEXT_ATTRIBUTE_OAUTH_ACCESS_TOKEN), eq(bearer));
    }

    @Test
    public void shouldCallOAuthResourceAndHandleResult() throws Exception {
        final HttpHeaders headers = new HttpHeaders();
        String bearer = UUID.randomUUID().toString();

        headers.setAll(new HashMap<String, String>() {
            {
                put("Authorization", "Bearer " + bearer);
            }
        });

        Oauth2Policy policy = new Oauth2Policy(oAuth2PolicyConfiguration);
        when(mockRequest.headers()).thenReturn(headers);
        when(mockExecutionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(oAuth2PolicyConfiguration.getOauthResource()).thenReturn("oauth2");
        when(resourceManager.getResource(oAuth2PolicyConfiguration.getOauthResource(), OAuth2Resource.class)).thenReturn(customOAuth2Resource);
        when(mockExecutionContext.getTemplateEngine()).thenReturn(templateEngine);

        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(customOAuth2Resource).introspect(eq(bearer), any(Handler.class));
        verify(mockExecutionContext).setAttribute(eq(Oauth2Policy.CONTEXT_ATTRIBUTE_OAUTH_ACCESS_TOKEN), eq(bearer));
    }

    @Test
    public void shouldValidScopes_noRequiredScopes() throws IOException {
        JsonNode jsonNode = readJsonResource("/io/gravitee/policy/oauth2/oauth2-response01.json");
        Collection<String> scopes = Oauth2Policy.extractScopes(jsonNode, DEFAULT_OAUTH_SCOPE_SEPARATOR);
        boolean valid = Oauth2Policy.hasRequiredScopes(scopes, null, false);
        Assert.assertTrue(valid);
    }

    @Test
    public void shouldNotValidScopes_emptyOAuthResponse() throws IOException {
        JsonNode jsonNode = readJsonResource("/io/gravitee/policy/oauth2/oauth2-response01.json");
        Collection<String> scopes = Oauth2Policy.extractScopes(jsonNode, DEFAULT_OAUTH_SCOPE_SEPARATOR);
        boolean valid = Oauth2Policy.hasRequiredScopes(scopes, Collections.singletonList("read"), false);
        Assert.assertFalse(valid);
    }

    @Test
    public void shouldValidScopes_emptyOAuthResponse() throws IOException {
        JsonNode jsonNode = readJsonResource("/io/gravitee/policy/oauth2/oauth2-response02.json");
        Collection<String> scopes = Oauth2Policy.extractScopes(jsonNode, DEFAULT_OAUTH_SCOPE_SEPARATOR);
        boolean valid = Oauth2Policy.hasRequiredScopes(scopes, Collections.singletonList("read"), false);
        Assert.assertTrue(valid);
    }

    @Test
    public void shouldValidScopes_stringOfScopes() throws IOException {
        JsonNode jsonNode = readJsonResource("/io/gravitee/policy/oauth2/oauth2-response04.json");
        Collection<String> scopes = Oauth2Policy.extractScopes(jsonNode, DEFAULT_OAUTH_SCOPE_SEPARATOR);
        boolean valid = Oauth2Policy.hasRequiredScopes(scopes, Collections.singletonList("read"), false);
        Assert.assertTrue(valid);
    }

    @Test
    public void shouldValidScopes_stringOfScopes_moreOauthScope() throws IOException {
        JsonNode jsonNode = readJsonResource("/io/gravitee/policy/oauth2/oauth2-response08.json");
        Collection<String> scopes = Oauth2Policy.extractScopes(jsonNode, DEFAULT_OAUTH_SCOPE_SEPARATOR);
        boolean valid = Oauth2Policy.hasRequiredScopes(scopes, Arrays.asList("read", "functional-settings"), true);
        Assert.assertTrue(valid);
    }

    @Test
    public void shouldValidScopes_stringOfScopes_customSeparator() throws IOException {
        JsonNode jsonNode = readJsonResource("/io/gravitee/policy/oauth2/oauth2-response06.json");
        Collection<String> scopes = Oauth2Policy.extractScopes(jsonNode, ",");
        boolean valid = Oauth2Policy.hasRequiredScopes(scopes, Collections.singletonList("read"), false);
        Assert.assertTrue(valid);
    }

    @Test
    public void shouldValidScopes_arrayOfScope() throws IOException {
        JsonNode jsonNode = readJsonResource("/io/gravitee/policy/oauth2/oauth2-response05.json");
        Collection<String> scopes = Oauth2Policy.extractScopes(jsonNode, DEFAULT_OAUTH_SCOPE_SEPARATOR);
        boolean valid = Oauth2Policy.hasRequiredScopes(scopes, Collections.singletonList("read"), false);
        Assert.assertTrue(valid);
    }

    @Test
    public void shouldValidScopes_arrayOfScopes() throws IOException {
        JsonNode jsonNode = readJsonResource("/io/gravitee/policy/oauth2/oauth2-response07.json");
        Collection<String> scopes = Oauth2Policy.extractScopes(jsonNode, DEFAULT_OAUTH_SCOPE_SEPARATOR);
        boolean valid = Oauth2Policy.hasRequiredScopes(scopes, Arrays.asList("read", "write"), false);
        Assert.assertTrue(valid);
    }

    @Test
    public void shouldValidScopes_arrayOfScopes_strict() throws IOException {
        JsonNode jsonNode = readJsonResource("/io/gravitee/policy/oauth2/oauth2-response05.json");
        Collection<String> scopes = Oauth2Policy.extractScopes(jsonNode, DEFAULT_OAUTH_SCOPE_SEPARATOR);
        boolean valid = Oauth2Policy.hasRequiredScopes(scopes, Arrays.asList("read", "write", "admin"), true);
        Assert.assertTrue(valid);
    }

    @Test
    public void shoulValidScopes_arrayOfScope_strict() throws IOException {
        JsonNode jsonNode = readJsonResource("/io/gravitee/policy/oauth2/oauth2-response05.json");
        Collection<String> scopes = Oauth2Policy.extractScopes(jsonNode, DEFAULT_OAUTH_SCOPE_SEPARATOR);
        boolean valid = Oauth2Policy.hasRequiredScopes(scopes, Collections.singletonList("read"), true);
        Assert.assertTrue(valid);
    }

    @Test
    public void shouldValidScopes_arrayOfScopes_strict2() throws IOException {
        JsonNode jsonNode = readJsonResource("/io/gravitee/policy/oauth2/oauth2-response05.json");
        Collection<String> scopes = Oauth2Policy.extractScopes(jsonNode, DEFAULT_OAUTH_SCOPE_SEPARATOR);
        boolean valid = Oauth2Policy.hasRequiredScopes(scopes, Arrays.asList("read", "write"), true);
        Assert.assertTrue(valid);
    }

    @Test
    public void shouldFail_badIntrospection() throws IOException {
        HttpHeaders httpHeaders = mock(HttpHeaders.class);
        when(mockResponse.headers()).thenReturn(httpHeaders);

        Oauth2Policy policy = new Oauth2Policy(oAuth2PolicyConfiguration);
        Handler<OAuth2Response> handler = policy.handleResponse(mockPolicychain, mockRequest, mockResponse, mockExecutionContext);

        String payload = readResource("/io/gravitee/policy/oauth2/oauth2-response03.json");
        handler.handle(new OAuth2Response(false, payload));

        verify(mockExecutionContext, never()).setAttribute(eq(Oauth2Policy.CONTEXT_ATTRIBUTE_CLIENT_ID), anyString());
        verify(httpHeaders).add(eq(HttpHeaders.WWW_AUTHENTICATE), anyString());

        verify(mockPolicychain).failWith(argThat(result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401
                && Oauth2Policy.OAUTH2_INVALID_ACCESS_TOKEN_KEY.equals(result.key())));
    }

    @Test
    public void shouldFail_exception() throws IOException {
        HttpHeaders httpHeaders = mock(HttpHeaders.class);
        when(mockResponse.headers()).thenReturn(httpHeaders);

        Oauth2Policy policy = new Oauth2Policy(oAuth2PolicyConfiguration);
        Handler<OAuth2Response> handler = policy.handleResponse(mockPolicychain, mockRequest, mockResponse, mockExecutionContext);

        handler.handle(new OAuth2Response(new Exception()));

        verify(mockExecutionContext, never()).setAttribute(eq(Oauth2Policy.CONTEXT_ATTRIBUTE_CLIENT_ID), anyString());
        verify(httpHeaders).add(eq(HttpHeaders.WWW_AUTHENTICATE), anyString());

        verify(mockPolicychain).failWith(argThat(result -> result.statusCode() == HttpStatusCode.SERVICE_UNAVAILABLE_503
                && Oauth2Policy.OAUTH2_SERVER_UNAVAILABLE_KEY.equals(result.key())));
    }

    @Test
    public void shouldFail_invalidResponseFormat() throws IOException {
        HttpHeaders httpHeaders = mock(HttpHeaders.class);
        when(mockResponse.headers()).thenReturn(httpHeaders);

        Oauth2Policy policy = new Oauth2Policy(oAuth2PolicyConfiguration);
        Handler<OAuth2Response> handler = policy.handleResponse(mockPolicychain, mockRequest, mockResponse, mockExecutionContext);

        handler.handle(new OAuth2Response(true, "blablabla"));

        verify(mockExecutionContext, never()).setAttribute(eq(Oauth2Policy.CONTEXT_ATTRIBUTE_CLIENT_ID), anyString());
        verify(httpHeaders).add(eq(HttpHeaders.WWW_AUTHENTICATE), anyString());

        verify(mockPolicychain).failWith(argThat(result -> result.statusCode() == HttpStatusCode.FORBIDDEN_403
                && Oauth2Policy.OAUTH2_INVALID_SERVER_RESPONSE_KEY.equals(result.key())));
    }

    @Test
    public void shouldFail_goodIntrospection_noClientId() throws IOException {
        HttpHeaders httpHeaders = mock(HttpHeaders.class);

        Oauth2Policy policy = new Oauth2Policy(oAuth2PolicyConfiguration);
        when(oAuth2PolicyConfiguration.getOauthResource()).thenReturn("oauth2");
        when(mockExecutionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(resourceManager.getResource(oAuth2PolicyConfiguration.getOauthResource(), OAuth2Resource.class)).thenReturn(customOAuth2Resource);
        when(customOAuth2Resource.getScopeSeparator()).thenReturn(DEFAULT_OAUTH_SCOPE_SEPARATOR);
        Handler<OAuth2Response> handler = policy.handleResponse(mockPolicychain, mockRequest, mockResponse, mockExecutionContext);

        String payload = readResource("/io/gravitee/policy/oauth2/oauth2-response03.json");
        handler.handle(new OAuth2Response(true, payload));

        verify(mockExecutionContext, never()).setAttribute(eq(Oauth2Policy.CONTEXT_ATTRIBUTE_CLIENT_ID), anyString());
        verify(httpHeaders, never()).add(eq(HttpHeaders.WWW_AUTHENTICATE), anyString());
        verify(mockPolicychain).doNext(mockRequest, mockResponse);
    }

    @Test
    public void shouldValidate_goodIntrospection_withClientId() throws IOException {
        when(oAuth2PolicyConfiguration.isExtractPayload()).thenReturn(true);

        Oauth2Policy policy = new Oauth2Policy(oAuth2PolicyConfiguration);
        when(mockExecutionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(resourceManager.getResource(oAuth2PolicyConfiguration.getOauthResource(), OAuth2Resource.class)).thenReturn(customOAuth2Resource);
        when(customOAuth2Resource.getScopeSeparator()).thenReturn(DEFAULT_OAUTH_SCOPE_SEPARATOR);

        Handler<OAuth2Response> handler = policy.handleResponse(mockPolicychain, mockRequest, mockResponse, mockExecutionContext);

        String payload = readResource("/io/gravitee/policy/oauth2/oauth2-response04.json");
        handler.handle(new OAuth2Response(true, payload));

        verify(mockExecutionContext).setAttribute(Oauth2Policy.CONTEXT_ATTRIBUTE_CLIENT_ID, "my-client-id");
        verify(mockExecutionContext).setAttribute(Oauth2Policy.CONTEXT_ATTRIBUTE_OAUTH_PAYLOAD, payload);
        verify(mockExecutionContext).setAttribute(eq(ExecutionContext.ATTR_USER_ROLES), argThat(new ArgumentMatcher<List<String>>() {
            @Override
            public boolean matches(List<String> scopes) {
                return
                        scopes.get(0).equals("read") &&
                                scopes.get(1).equals("write") &&
                                scopes.get(2).equals("admin");
            }
        }));
        verify(mockPolicychain).doNext(mockRequest, mockResponse);
    }

    @Test
    public void shouldValidate_goodIntrospection_withClientId_validScopes() throws IOException {
        when(oAuth2PolicyConfiguration.isCheckRequiredScopes()).thenReturn(true);
        when(mockExecutionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(resourceManager.getResource(oAuth2PolicyConfiguration.getOauthResource(), OAuth2Resource.class)).thenReturn(customOAuth2Resource);
        when(customOAuth2Resource.getScopeSeparator()).thenReturn(DEFAULT_OAUTH_SCOPE_SEPARATOR);

        Oauth2Policy policy = new Oauth2Policy(oAuth2PolicyConfiguration);
        Handler<OAuth2Response> handler = policy.handleResponse(mockPolicychain, mockRequest, mockResponse, mockExecutionContext);

        String payload = readResource("/io/gravitee/policy/oauth2/oauth2-response04.json");
        handler.handle(new OAuth2Response(true, payload));

        verify(mockExecutionContext).setAttribute(Oauth2Policy.CONTEXT_ATTRIBUTE_CLIENT_ID, "my-client-id");
        verify(mockPolicychain).doNext(mockRequest, mockResponse);
    }

    @Test
    public void shouldValidate_goodIntrospection_withClientId_invalidScopes() throws IOException {
        HttpHeaders httpHeaders = mock(HttpHeaders.class);
        when(mockResponse.headers()).thenReturn(httpHeaders);
        when(oAuth2PolicyConfiguration.isCheckRequiredScopes()).thenReturn(true);
        when(oAuth2PolicyConfiguration.getRequiredScopes()).thenReturn(Collections.singletonList("super-admin"));
        when(mockExecutionContext.getComponent(ResourceManager.class)).thenReturn(resourceManager);
        when(resourceManager.getResource(oAuth2PolicyConfiguration.getOauthResource(), OAuth2Resource.class)).thenReturn(customOAuth2Resource);
        when(customOAuth2Resource.getScopeSeparator()).thenReturn(DEFAULT_OAUTH_SCOPE_SEPARATOR);

        Oauth2Policy policy = new Oauth2Policy(oAuth2PolicyConfiguration);
        Handler<OAuth2Response> handler = policy.handleResponse(mockPolicychain, mockRequest, mockResponse, mockExecutionContext);

        String payload = readResource("/io/gravitee/policy/oauth2/oauth2-response04.json");
        handler.handle(new OAuth2Response(true, payload));

        verify(mockPolicychain).failWith(argThat(result -> result.statusCode() == HttpStatusCode.FORBIDDEN_403
                && Oauth2Policy.OAUTH2_INSUFFICIENT_SCOPE_KEY.equals(result.key())));
    }

    private JsonNode readJsonResource(String resource) throws IOException {
        return Oauth2Policy.MAPPER.readTree(this.getClass().getResourceAsStream(resource));
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