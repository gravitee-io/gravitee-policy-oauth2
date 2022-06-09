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

import static io.gravitee.gateway.api.ExecutionContext.ATTR_USER;
import static io.gravitee.gateway.api.ExecutionContext.ATTR_USER_ROLES;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.common.http.MediaType;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.handler.Handler;
import io.gravitee.gateway.api.http.HttpHeaderNames;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequest;
import io.gravitee.policy.api.annotations.RequireResource;
import io.gravitee.policy.oauth2.configuration.OAuth2PolicyConfiguration;
import io.gravitee.policy.oauth2.resource.CacheElement;
import io.gravitee.resource.api.ResourceManager;
import io.gravitee.resource.cache.api.CacheResource;
import io.gravitee.resource.cache.api.Element;
import io.gravitee.resource.oauth2.api.OAuth2Resource;
import io.gravitee.resource.oauth2.api.OAuth2Response;
import java.io.IOException;
import java.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
@RequireResource
public class Oauth2PolicyV3 {

    private final Logger logger = LoggerFactory.getLogger(Oauth2PolicyV3.class);

    public static final String BEARER_AUTHORIZATION_TYPE = "Bearer";
    public static final String OAUTH_PAYLOAD_SCOPE_NODE = "scope";
    public static final String OAUTH_PAYLOAD_CLIENT_ID_NODE = "client_id";
    public static final String OAUTH_PAYLOAD_SUB_NODE = "sub";
    public static final String OAUTH_PAYLOAD_EXP = "exp";

    public static final String CONTEXT_ATTRIBUTE_PREFIX = "oauth.";
    public static final String CONTEXT_ATTRIBUTE_OAUTH_PAYLOAD = CONTEXT_ATTRIBUTE_PREFIX + "payload";
    public static final String CONTEXT_ATTRIBUTE_OAUTH_ACCESS_TOKEN = CONTEXT_ATTRIBUTE_PREFIX + "access_token";
    public static final String CONTEXT_ATTRIBUTE_CLIENT_ID = CONTEXT_ATTRIBUTE_PREFIX + "client_id";

    public static final String OAUTH2_MISSING_SERVER_KEY = "OAUTH2_MISSING_SERVER";
    public static final String OAUTH2_MISSING_HEADER_KEY = "OAUTH2_MISSING_HEADER";
    public static final String OAUTH2_MISSING_ACCESS_TOKEN_KEY = "OAUTH2_MISSING_ACCESS_TOKEN";
    public static final String OAUTH2_INVALID_ACCESS_TOKEN_KEY = "OAUTH2_INVALID_ACCESS_TOKEN";
    public static final String OAUTH2_INVALID_SERVER_RESPONSE_KEY = "OAUTH2_INVALID_SERVER_RESPONSE";
    public static final String OAUTH2_INSUFFICIENT_SCOPE_KEY = "OAUTH2_INSUFFICIENT_SCOPE";
    public static final String OAUTH2_SERVER_UNAVAILABLE_KEY = "OAUTH2_SERVER_UNAVAILABLE";

    static final ObjectMapper MAPPER = new ObjectMapper();

    protected final OAuth2PolicyConfiguration oAuth2PolicyConfiguration;

    public Oauth2PolicyV3(OAuth2PolicyConfiguration oAuth2PolicyConfiguration) {
        this.oAuth2PolicyConfiguration = oAuth2PolicyConfiguration;
    }

    @OnRequest
    public void onRequest(Request request, Response response, ExecutionContext executionContext, PolicyChain policyChain) {
        logger.debug("Read access_token from request {}", request.id());

        oAuth2PolicyConfiguration.setOauthResource(
            executionContext.getTemplateEngine().getValue(oAuth2PolicyConfiguration.getOauthResource(), String.class)
        );

        OAuth2Resource oauth2 = executionContext
            .getComponent(ResourceManager.class)
            .getResource(oAuth2PolicyConfiguration.getOauthResource(), OAuth2Resource.class);

        if (oauth2 == null) {
            policyChain.failWith(
                PolicyResult.failure(
                    OAUTH2_MISSING_SERVER_KEY,
                    HttpStatusCode.UNAUTHORIZED_401,
                    "No OAuth authorization server has been configured"
                )
            );
            return;
        }

        String authorizationHeader = request.headers().get(HttpHeaderNames.AUTHORIZATION);

        if (
            authorizationHeader == null ||
            authorizationHeader.isEmpty() ||
            !StringUtils.startsWithIgnoreCase(authorizationHeader, BEARER_AUTHORIZATION_TYPE)
        ) {
            sendError(OAUTH2_MISSING_HEADER_KEY, response, policyChain, "invalid_request", "No OAuth authorization header was supplied");
            return;
        }

        String accessToken = authorizationHeader.substring(BEARER_AUTHORIZATION_TYPE.length()).trim();
        if (accessToken.isEmpty()) {
            sendError(OAUTH2_MISSING_ACCESS_TOKEN_KEY, response, policyChain, "invalid_request", "No OAuth access token was supplied");
            return;
        }

        // Set access_token in context
        executionContext.setAttribute(CONTEXT_ATTRIBUTE_OAUTH_ACCESS_TOKEN, accessToken);

        CacheResource<?> cacheResource = executionContext
            .getComponent(ResourceManager.class)
            .getResource(oAuth2PolicyConfiguration.getOauthCacheResource(), CacheResource.class);

        if (cacheResource != null) {
            Element element = cacheResource.getCache(executionContext).get(accessToken);
            if (element != null) {
                String oauth2payload = (String) element.value();
                handleSuccess(policyChain, request, response, executionContext, oauth2payload, null);
            } else {
                oauth2.introspect(accessToken, handleResponse(policyChain, request, response, executionContext, cacheResource));
            }
        } else {
            // Validate access token
            oauth2.introspect(accessToken, handleResponse(policyChain, request, response, executionContext, null));
        }

        if (!oAuth2PolicyConfiguration.isPropagateAuthHeader()) {
            request.headers().remove(HttpHeaderNames.AUTHORIZATION);
        }
    }

    Handler<OAuth2Response> handleResponse(
        PolicyChain policyChain,
        Request request,
        Response response,
        ExecutionContext executionContext,
        CacheResource cacheResource
    ) {
        return oauth2response -> {
            if (oauth2response.isSuccess()) {
                handleSuccess(policyChain, request, response, executionContext, oauth2response.getPayload(), cacheResource);
            } else {
                response.headers().add(HttpHeaderNames.WWW_AUTHENTICATE, BEARER_AUTHORIZATION_TYPE + " realm=gravitee.io ");

                if (oauth2response.getThrowable() == null) {
                    policyChain.failWith(
                        PolicyResult.failure(
                            OAUTH2_INVALID_ACCESS_TOKEN_KEY,
                            HttpStatusCode.UNAUTHORIZED_401,
                            oauth2response.getPayload(),
                            MediaType.APPLICATION_JSON
                        )
                    );
                } else {
                    policyChain.failWith(
                        PolicyResult.failure(
                            OAUTH2_SERVER_UNAVAILABLE_KEY,
                            HttpStatusCode.SERVICE_UNAVAILABLE_503,
                            "temporarily_unavailable"
                        )
                    );
                }
            }
        };
    }

    private void handleSuccess(
        PolicyChain policyChain,
        Request request,
        Response response,
        ExecutionContext executionContext,
        String oauth2payload,
        CacheResource cacheResource
    ) {
        JsonNode oauthResponseNode = readPayload(oauth2payload);

        if (oauthResponseNode == null) {
            sendError(
                OAUTH2_INVALID_SERVER_RESPONSE_KEY,
                response,
                policyChain,
                "server_error",
                "Invalid response from authorization server"
            );
            return;
        }

        // Extract client_id
        String clientId = oauthResponseNode.path(OAUTH_PAYLOAD_CLIENT_ID_NODE).asText();
        if (clientId != null && !clientId.trim().isEmpty()) {
            executionContext.setAttribute(CONTEXT_ATTRIBUTE_CLIENT_ID, clientId);
        }

        final OAuth2Resource oauth2 = executionContext
            .getComponent(ResourceManager.class)
            .getResource(oAuth2PolicyConfiguration.getOauthResource(), OAuth2Resource.class);

        // Extract user
        final String user = oauthResponseNode.path(oauth2.getUserClaim() == null ? OAUTH_PAYLOAD_SUB_NODE : oauth2.getUserClaim()).asText();
        if (user != null && !user.trim().isEmpty()) {
            executionContext.setAttribute(ATTR_USER, user);
            request.metrics().setUser(user);
        }

        // Extract scopes from introspection response
        List<String> scopes = extractScopes(oauthResponseNode, oauth2.getScopeSeparator());
        executionContext.setAttribute(ATTR_USER_ROLES, scopes);

        // Check required scopes to access the resource
        if (oAuth2PolicyConfiguration.isCheckRequiredScopes()) {
            if (!hasRequiredScopes(scopes, oAuth2PolicyConfiguration.getRequiredScopes(), oAuth2PolicyConfiguration.isModeStrict())) {
                sendError(
                    OAUTH2_INSUFFICIENT_SCOPE_KEY,
                    response,
                    policyChain,
                    "insufficient_scope",
                    "The request requires higher privileges than provided by the access token."
                );
                return;
            }
        }

        // Store OAuth2 payload into execution context if required
        if (oAuth2PolicyConfiguration.isExtractPayload()) {
            executionContext.setAttribute(CONTEXT_ATTRIBUTE_OAUTH_PAYLOAD, oauth2payload);
        }

        if (cacheResource != null) {
            String accessToken = (String) executionContext.getAttribute(CONTEXT_ATTRIBUTE_OAUTH_ACCESS_TOKEN);
            CacheElement element = new CacheElement(accessToken, oauth2payload);
            if (oauthResponseNode.has(OAUTH_PAYLOAD_EXP)) {
                long expTimestamp = oauthResponseNode.get(OAUTH_PAYLOAD_EXP).asLong();
                long ttl = expTimestamp - System.currentTimeMillis() / 1000L;
                element.setTimeToLive(Long.valueOf(ttl).intValue());
            }
            cacheResource.getCache(executionContext).put(element);
        }

        // Continue chaining
        policyChain.doNext(request, response);
    }

    /**
     * As per https://tools.ietf.org/html/rfc6750#page-7:
     *
     *      HTTP/1.1 401 Unauthorized
     *      WWW-Authenticate: Bearer realm="example",
     *      error="invalid_token",
     *      error_description="The access token expired"
     */
    private void sendError(String responseKey, Response response, PolicyChain policyChain, String error, String description) {
        String headerValue =
            BEARER_AUTHORIZATION_TYPE +
            " realm=\"gravitee.io\"," +
            " error=\"" +
            error +
            "\"," +
            " error_description=\"" +
            description +
            "\"";
        response.headers().add(HttpHeaderNames.WWW_AUTHENTICATE, headerValue);
        policyChain.failWith(PolicyResult.failure(responseKey, HttpStatusCode.UNAUTHORIZED_401, null));
    }

    protected JsonNode readPayload(String oauthPayload) {
        try {
            return MAPPER.readTree(oauthPayload);
        } catch (IOException ioe) {
            logger.error("Unable to check required scope from introspection endpoint payload: {}", oauthPayload);
            return null;
        }
    }

    protected static List<String> extractScopes(JsonNode oauthResponseNode, String scopeSeparator) {
        JsonNode scopesNode = oauthResponseNode.path(OAUTH_PAYLOAD_SCOPE_NODE);

        List<String> scopes;

        if (scopesNode instanceof ArrayNode) {
            Iterator<JsonNode> scopeIterator = scopesNode.elements();
            scopes = new ArrayList<>(scopesNode.size());
            List<String> finalScopes = scopes;
            scopeIterator.forEachRemaining(jsonNode -> finalScopes.add(jsonNode.asText()));
        } else {
            scopes = Arrays.asList(scopesNode.asText().split(scopeSeparator));
        }

        return scopes;
    }

    protected static boolean hasRequiredScopes(Collection<String> tokenScopes, List<String> requiredScopes, final boolean modeStrict) {
        if (requiredScopes == null || requiredScopes.isEmpty()) {
            return true;
        }

        if (tokenScopes == null || tokenScopes.isEmpty()) {
            return false;
        }

        if (modeStrict) {
            return tokenScopes.containsAll(requiredScopes);
        } else {
            return tokenScopes.stream().anyMatch(requiredScopes::contains);
        }
    }
}
