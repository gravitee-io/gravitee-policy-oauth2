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

import static io.gravitee.common.http.HttpStatusCode.SERVICE_UNAVAILABLE_503;
import static io.gravitee.common.http.HttpStatusCode.UNAUTHORIZED_401;
import static io.gravitee.gateway.api.ExecutionContext.ATTR_USER;
import static io.gravitee.gateway.api.ExecutionContext.ATTR_USER_ROLES;

import com.fasterxml.jackson.databind.JsonNode;
import io.gravitee.common.http.MediaType;
import io.gravitee.common.security.jwt.LazyJWT;
import io.gravitee.gateway.api.http.HttpHeaderNames;
import io.gravitee.gateway.jupiter.api.ExecutionFailure;
import io.gravitee.gateway.jupiter.api.context.HttpExecutionContext;
import io.gravitee.gateway.jupiter.api.context.MessageExecutionContext;
import io.gravitee.gateway.jupiter.api.context.RequestExecutionContext;
import io.gravitee.gateway.jupiter.api.policy.SecurityPolicy;
import io.gravitee.policy.api.annotations.RequireResource;
import io.gravitee.policy.oauth2.configuration.OAuth2PolicyConfiguration;
import io.gravitee.policy.oauth2.resource.CacheElement;
import io.gravitee.policy.oauth2.utils.TokenExtractor;
import io.gravitee.policy.v3.oauth2.Oauth2PolicyV3;
import io.gravitee.resource.api.ResourceManager;
import io.gravitee.resource.cache.api.CacheResource;
import io.gravitee.resource.cache.api.Element;
import io.gravitee.resource.oauth2.api.OAuth2Resource;
import io.gravitee.resource.oauth2.api.OAuth2Response;
import io.reactivex.Completable;
import io.reactivex.Maybe;
import io.reactivex.Single;
import java.util.List;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
@RequireResource
public class Oauth2Policy extends Oauth2PolicyV3 implements SecurityPolicy {

    public static final String CONTEXT_ATTRIBUTE_JWT = "jwt";
    public static final String CONTEXT_ATTRIBUTE_TOKEN = CONTEXT_ATTRIBUTE_PREFIX + "token";
    public static final String OAUTH2_ERROR_ACCESS_DENIED = "access_denied";
    public static final String GATEWAY_OAUTH2_ACCESS_DENIED_KEY = "GATEWAY_OAUTH2_ACCESS_DENIED";
    protected static final String NO_OAUTH_SERVER_CONFIGURED_MESSAGE = "No OAuth authorization server has been configured";
    protected static final String NO_AUTHORIZATION_HEADER_SUPPLIED_MESSAGE = "No OAuth authorization header was supplied";
    protected static final String TEMPORARILY_UNAVAILABLE_MESSAGE = "temporarily_unavailable";
    protected static final String INVALID_SERVER_RESPONSE_MESSAGE = "Invalid response from authorization server";
    protected static final String INSUFFICIENT_SCOPES_MESSAGE = "The request requires higher privileges than provided by the access token.";
    private static final Logger log = LoggerFactory.getLogger(Oauth2Policy.class);
    private static final Single<Boolean> TRUE = Single.just(true);

    public Oauth2Policy(OAuth2PolicyConfiguration oAuth2PolicyConfiguration) {
        super(oAuth2PolicyConfiguration);
    }

    @Override
    public String id() {
        return "oauth2";
    }

    @Override
    public int order() {
        return 0;
    }

    @Override
    public Single<Boolean> support(HttpExecutionContext ctx) {
        final LazyJWT jwtToken = ctx.getAttribute(CONTEXT_ATTRIBUTE_JWT);
        if (jwtToken != null) {
            return TRUE;
        }

        final Optional<String> optToken = TokenExtractor.extract(ctx.request());
        optToken.ifPresent(token -> ctx.setAttribute(CONTEXT_ATTRIBUTE_JWT, new LazyJWT(token)));

        return Single.just(optToken.isPresent());
    }

    @Override
    public boolean requireSubscription() {
        return true;
    }

    @Override
    public Completable onInvalidSubscription(HttpExecutionContext ctx) {
        return ctx.interruptWith(
            new ExecutionFailure(UNAUTHORIZED_401).key(GATEWAY_OAUTH2_ACCESS_DENIED_KEY).message(OAUTH2_ERROR_ACCESS_DENIED)
        );
    }

    @Override
    public Completable onRequest(final RequestExecutionContext ctx) {
        return handleSecurity(ctx);
    }

    @Override
    public Completable onMessageRequest(final MessageExecutionContext ctx) {
        return handleSecurity(ctx);
    }

    private Completable handleSecurity(final HttpExecutionContext ctx) {
        return Completable
            .defer(
                () -> {
                    log.debug("Read access_token from request {}", ctx.request().id());
                    final OAuth2Resource<?> oauth2Resource = getOauth2Resource(ctx);

                    if (oauth2Resource == null) {
                        return ctx.interruptWith(
                            new ExecutionFailure(UNAUTHORIZED_401)
                                .key(OAUTH2_MISSING_SERVER_KEY)
                                .message(NO_OAUTH_SERVER_CONFIGURED_MESSAGE)
                        );
                    }

                    return extractToken(ctx)
                        .flatMapCompletable(
                            accessToken -> {
                                // Set access_token in context
                                ctx.setAttribute(CONTEXT_ATTRIBUTE_OAUTH_ACCESS_TOKEN, accessToken);

                                final CacheResource<?> cacheResource = getCacheResource(ctx);

                                if (cacheResource != null) {
                                    Element element = cacheResource.getCache(ctx).get(accessToken);
                                    if (element != null) {
                                        return validateOAuth2Payload(ctx, (String) element.value(), cacheResource, oauth2Resource);
                                    }
                                }
                                // Validate access token
                                return introspectAccessToken(ctx, accessToken, cacheResource, oauth2Resource);
                            }
                        );
                }
            )
            .doOnTerminate(
                () -> {
                    if (!oAuth2PolicyConfiguration.isPropagateAuthHeader()) {
                        ctx.request().headers().remove(HttpHeaderNames.AUTHORIZATION);
                    }
                }
            );
    }

    private Maybe<String> extractToken(HttpExecutionContext ctx) {
        return Maybe
            .defer(
                () -> {
                    Optional<LazyJWT> jwt = Optional.ofNullable(ctx.getAttribute(CONTEXT_ATTRIBUTE_JWT));

                    if (jwt.isEmpty()) {
                        Optional<String> token = TokenExtractor.extract(ctx.request());

                        if (token.isEmpty()) {
                            return sendError(ctx, OAUTH2_MISSING_HEADER_KEY, "invalid_request", NO_AUTHORIZATION_HEADER_SUPPLIED_MESSAGE)
                                .toMaybe();
                        }

                        jwt = Optional.of(new LazyJWT(token.get()));
                    }

                    final String accessToken = jwt.get().getToken();
                    if (accessToken.isBlank()) {
                        return sendError(ctx, OAUTH2_MISSING_ACCESS_TOKEN_KEY, "invalid_request", NO_AUTHORIZATION_HEADER_SUPPLIED_MESSAGE)
                            .toMaybe();
                    }

                    return Maybe.just(accessToken);
                }
            )
            .doOnSuccess(token -> ctx.setAttribute(CONTEXT_ATTRIBUTE_TOKEN, token));
    }

    private Completable validateOAuth2Payload(
        HttpExecutionContext ctx,
        String oauth2payload,
        CacheResource<?> cacheResource,
        OAuth2Resource<?> oauth2Resource
    ) {
        JsonNode oauthResponseNode = readPayload(oauth2payload);

        if (oauthResponseNode == null) {
            return sendError(ctx, OAUTH2_INVALID_SERVER_RESPONSE_KEY, "server_error", INVALID_SERVER_RESPONSE_MESSAGE);
        }

        // Extract client_id
        String clientId = oauthResponseNode.path(OAUTH_PAYLOAD_CLIENT_ID_NODE).asText();
        if (clientId != null && !clientId.trim().isEmpty()) {
            ctx.setAttribute(CONTEXT_ATTRIBUTE_CLIENT_ID, clientId);
        }

        // Extract user
        final String user = oauthResponseNode
            .path(oauth2Resource.getUserClaim() == null ? OAUTH_PAYLOAD_SUB_NODE : oauth2Resource.getUserClaim())
            .asText();
        if (user != null && !user.trim().isEmpty()) {
            ctx.setAttribute(ATTR_USER, user);
            ctx.request().metrics().setUser(user);
        }

        // Extract scopes from introspection response
        List<String> scopes = extractScopes(oauthResponseNode, oauth2Resource.getScopeSeparator());
        ctx.setAttribute(ATTR_USER_ROLES, scopes);

        // Check required scopes to access the resource
        if (oAuth2PolicyConfiguration.isCheckRequiredScopes()) {
            if (!hasRequiredScopes(scopes, oAuth2PolicyConfiguration.getRequiredScopes(), oAuth2PolicyConfiguration.isModeStrict())) {
                return sendError(ctx, OAUTH2_INSUFFICIENT_SCOPE_KEY, "insufficient_scope", INSUFFICIENT_SCOPES_MESSAGE);
            }
        }

        // Store OAuth2 payload into execution context if required
        if (oAuth2PolicyConfiguration.isExtractPayload()) {
            ctx.setAttribute(CONTEXT_ATTRIBUTE_OAUTH_PAYLOAD, oauth2payload);
        }

        if (cacheResource != null) {
            String accessToken = ctx.getAttribute(CONTEXT_ATTRIBUTE_OAUTH_ACCESS_TOKEN);
            CacheElement element = new CacheElement(accessToken, oauth2payload);
            if (oauthResponseNode.has(OAUTH_PAYLOAD_EXP)) {
                long expTimestamp = oauthResponseNode.get(OAUTH_PAYLOAD_EXP).asLong();
                long ttl = expTimestamp - System.currentTimeMillis() / 1000L;
                element.setTimeToLive(Long.valueOf(ttl).intValue());
            }
            cacheResource.getCache(ctx).put(element);
        }

        // Continue chaining
        return Completable.complete();
    }

    private Completable introspectAccessToken(
        HttpExecutionContext ctx,
        String accessToken,
        CacheResource<?> cacheResource,
        OAuth2Resource<?> oauth2Resource
    ) {
        return Single
            .<OAuth2Response>create(emitter -> oauth2Resource.introspect(accessToken, emitter::onSuccess))
            .flatMapCompletable(
                oauth2Response -> {
                    if (oauth2Response.isSuccess()) {
                        return validateOAuth2Payload(ctx, oauth2Response.getPayload(), cacheResource, oauth2Resource);
                    } else {
                        ctx.response().headers().add(HttpHeaderNames.WWW_AUTHENTICATE, BEARER_AUTHORIZATION_TYPE + " realm=gravitee.io ");

                        if (oauth2Response.getThrowable() == null) {
                            return ctx.interruptWith(
                                new ExecutionFailure(UNAUTHORIZED_401)
                                    .key(OAUTH2_INVALID_ACCESS_TOKEN_KEY)
                                    .message(oauth2Response.getPayload())
                                    .contentType(MediaType.APPLICATION_JSON)
                            );
                        } else {
                            return ctx.interruptWith(
                                new ExecutionFailure(SERVICE_UNAVAILABLE_503)
                                    .key(OAUTH2_SERVER_UNAVAILABLE_KEY)
                                    .message(TEMPORARILY_UNAVAILABLE_MESSAGE)
                            );
                        }
                    }
                }
            );
    }

    /**
     * As per https://tools.ietf.org/html/rfc6750#page-7:
     *
     *      HTTP/1.1 401 Unauthorized
     *      WWW-Authenticate: Bearer realm="example",
     *      error="invalid_token",
     *      error_description="The access token expired"
     */
    private Completable sendError(HttpExecutionContext ctx, String responseKey, String error, String description) {
        String headerValue =
            BEARER_AUTHORIZATION_TYPE +
            " realm=\"gravitee.io\"," +
            " error=\"" +
            error +
            "\"," +
            " error_description=\"" +
            description +
            "\"";

        ctx.response().headers().add(HttpHeaderNames.WWW_AUTHENTICATE, headerValue);

        return ctx.interruptWith(new ExecutionFailure(UNAUTHORIZED_401).key(responseKey).message(description));
    }

    private OAuth2Resource<?> getOauth2Resource(HttpExecutionContext ctx) {
        if (oAuth2PolicyConfiguration.getOauthResource() == null) {
            return null;
        }

        return ctx
            .getComponent(ResourceManager.class)
            .getResource(
                ctx.getTemplateEngine().getValue(oAuth2PolicyConfiguration.getOauthResource(), String.class),
                OAuth2Resource.class
            );
    }

    private CacheResource<?> getCacheResource(HttpExecutionContext ctx) {
        if (oAuth2PolicyConfiguration.getOauthCacheResource() == null) {
            return null;
        }

        return ctx.getComponent(ResourceManager.class).getResource(oAuth2PolicyConfiguration.getOauthCacheResource(), CacheResource.class);
    }
}
