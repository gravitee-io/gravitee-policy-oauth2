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

import io.gravitee.common.http.MediaType;
import io.gravitee.common.security.jwt.LazyJWT;
import io.gravitee.gateway.api.http.HttpHeaderNames;
import io.gravitee.gateway.jupiter.api.ExecutionFailure;
import io.gravitee.gateway.jupiter.api.context.HttpExecutionContext;
import io.gravitee.gateway.jupiter.api.policy.SecurityPolicy;
import io.gravitee.gateway.jupiter.api.policy.SecurityToken;
import io.gravitee.policy.api.annotations.RequireResource;
import io.gravitee.policy.oauth2.configuration.OAuth2PolicyConfiguration;
import io.gravitee.policy.oauth2.introspection.TokenIntrospectionCache;
import io.gravitee.policy.oauth2.introspection.TokenIntrospectionResult;
import io.gravitee.policy.oauth2.resource.CacheElement;
import io.gravitee.policy.oauth2.utils.TokenExtractor;
import io.gravitee.policy.v3.oauth2.Oauth2PolicyV3;
import io.gravitee.resource.api.ResourceManager;
import io.gravitee.resource.cache.api.Cache;
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

    public static final String ATTR_INTERNAL_TOKEN_INTROSPECTIONS = "token-introspection-cache";

    protected static final String NO_OAUTH_SERVER_CONFIGURED_MESSAGE = "No OAuth authorization server has been configured";
    protected static final String NO_AUTHORIZATION_HEADER_SUPPLIED_MESSAGE = "No OAuth authorization header was supplied";
    protected static final String TEMPORARILY_UNAVAILABLE_MESSAGE = "temporarily_unavailable";
    protected static final String INVALID_SERVER_RESPONSE_MESSAGE = "Invalid response from authorization server";
    protected static final String INSUFFICIENT_SCOPES_MESSAGE = "The request requires higher privileges than provided by the access token.";
    private static final Logger log = LoggerFactory.getLogger(Oauth2Policy.class);

    public Oauth2Policy(OAuth2PolicyConfiguration oAuth2PolicyConfiguration) {
        super(oAuth2PolicyConfiguration);
    }

    @Override
    public String id() {
        return "oauth2";
    }

    /**
     * {@inheritDoc}
     *
     * Order set to 100 to ensure it executes after the JWT policy.
     *
     * @return 100
     */
    @Override
    public int order() {
        return 100;
    }

    @Override
    public boolean requireSubscription() {
        return true;
    }

    @Override
    public Maybe<SecurityToken> extractSecurityToken(HttpExecutionContext ctx) {
        final OAuth2Resource<?> oauth2Resource = getOauth2Resource(ctx);
        if (oauth2Resource == null) {
            log.debug("Skipping security token extraction cause no oauth2 resource configured");
            return Maybe.empty();
        }

        return extractAccessToken(ctx, true)
            .flatMap(token -> introspectAccessToken(ctx, token, oauth2Resource).toMaybe())
            .flatMap(
                introspectionResult -> {
                    if (introspectionResult.hasClientId()) {
                        return Maybe.just(SecurityToken.forClientId(introspectionResult.getClientId()));
                    }
                    return Maybe.empty();
                }
            );
    }

    @Override
    public Completable onRequest(final HttpExecutionContext ctx) {
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

                    return extractAccessToken(ctx, false)
                        .switchIfEmpty(
                            Maybe.defer(
                                () ->
                                    sendError(ctx, OAUTH2_MISSING_HEADER_KEY, "invalid_request", NO_AUTHORIZATION_HEADER_SUPPLIED_MESSAGE)
                                        .toMaybe()
                            )
                        )
                        .flatMapCompletable(
                            accessToken -> {
                                if (accessToken.isBlank()) {
                                    return sendError(
                                        ctx,
                                        OAUTH2_MISSING_ACCESS_TOKEN_KEY,
                                        "invalid_request",
                                        NO_AUTHORIZATION_HEADER_SUPPLIED_MESSAGE
                                    );
                                }

                                // Set access_token in context
                                ctx.setAttribute(CONTEXT_ATTRIBUTE_OAUTH_ACCESS_TOKEN, accessToken);

                                // Introspect and validate access token
                                return introspectAndValidateAccessToken(ctx, accessToken, oauth2Resource);
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

    /**
     * Extract JWT token from request execution context.
     * Returns empty if no token found.
     *
     * @param ctx request execution context.
     * @param canUseCache allow retrieval of a previously extracted token from the request context cache
     * @return JWT token, or empty if no token found.
     */
    private Maybe<String> extractAccessToken(HttpExecutionContext ctx, boolean canUseCache) {
        return Maybe
            .defer(
                () -> {
                    LazyJWT jwt = canUseCache ? ctx.getAttribute(CONTEXT_ATTRIBUTE_JWT) : null;
                    if (jwt == null) {
                        Optional<String> token = TokenExtractor.extract(ctx.request());
                        if (token.isEmpty()) {
                            return Maybe.empty();
                        }
                        jwt = new LazyJWT(token.get());
                        ctx.setAttribute(CONTEXT_ATTRIBUTE_JWT, jwt);
                    }
                    return Maybe.just(jwt.getToken());
                }
            )
            .doOnSuccess(token -> ctx.setAttribute(CONTEXT_ATTRIBUTE_TOKEN, token));
    }

    private Completable validateOAuth2Payload(
        HttpExecutionContext ctx,
        TokenIntrospectionResult tokenIntrospectionResult,
        OAuth2Resource<?> oauth2Resource
    ) {
        if (!tokenIntrospectionResult.hasValidPayload()) {
            return sendError(ctx, OAUTH2_INVALID_SERVER_RESPONSE_KEY, "server_error", INVALID_SERVER_RESPONSE_MESSAGE);
        }

        if (tokenIntrospectionResult.hasClientId()) {
            ctx.setAttribute(CONTEXT_ATTRIBUTE_CLIENT_ID, tokenIntrospectionResult.getClientId());
        }

        String user = tokenIntrospectionResult.extractUser(oauth2Resource.getUserClaim());
        if (user != null && !user.trim().isEmpty()) {
            ctx.setAttribute(ATTR_USER, user);
            ctx.request().metrics().setUser(user);
        }

        List<String> scopes = tokenIntrospectionResult.extractScopes(oauth2Resource.getScopeSeparator());
        ctx.setAttribute(ATTR_USER_ROLES, scopes);

        // Check required scopes to access the resource
        if (oAuth2PolicyConfiguration.isCheckRequiredScopes()) {
            if (!hasRequiredScopes(scopes, oAuth2PolicyConfiguration.getRequiredScopes(), oAuth2PolicyConfiguration.isModeStrict())) {
                return sendError(ctx, OAUTH2_INSUFFICIENT_SCOPE_KEY, "insufficient_scope", INSUFFICIENT_SCOPES_MESSAGE);
            }
        }

        // Store OAuth2 payload into execution context if required
        if (oAuth2PolicyConfiguration.isExtractPayload()) {
            ctx.setAttribute(CONTEXT_ATTRIBUTE_OAUTH_PAYLOAD, tokenIntrospectionResult.getOauth2ResponsePayload());
        }

        // Continue chaining
        return Completable.complete();
    }

    /**
     * Calls given Oauth2 resource to introspect the given access token.
     * If introspection has already been realized on this Oauth2 resource for this request, it will return the cached response.
     *
     * @param accessToken access token to be introspected
     * @param oauth2Resource oauth2 resource
     * @return OAuth2Response
     */
    protected Single<TokenIntrospectionResult> introspectAccessToken(
        HttpExecutionContext ctx,
        String accessToken,
        OAuth2Resource<?> oauth2Resource
    ) {
        // find introspection in request context cache
        TokenIntrospectionCache tokenIntrospectionCache = getContextTokenIntrospectionCache(ctx);
        if (tokenIntrospectionCache.contains(accessToken, oauth2Resource)) {
            log.debug("Token as already been introspected by this Oauth resource on the current request. Re-using cached response.");
            return Single.just(tokenIntrospectionCache.get(accessToken, oauth2Resource).get());
        }

        // find introspection in policy cache
        final Cache policyCache = getPolicyTokenIntrospectionCache(ctx);
        if (policyCache != null) {
            Element element = policyCache.get(accessToken);
            if (element != null) {
                log.debug("Token as already been introspected in the policy level cache. Re-using cached response.");
                return Single.just(new TokenIntrospectionResult((String) element.value()));
            }
        }

        // or execute token introspection
        Single<OAuth2Response> oAuth2Response = Single.create(emitter -> oauth2Resource.introspect(accessToken, emitter::onSuccess));
        return oAuth2Response
            .map(TokenIntrospectionResult::new)
            .doOnSuccess(
                tokenIntrospectionResult ->
                    fillTokenIntrospectionCache(accessToken, oauth2Resource, tokenIntrospectionCache, policyCache, tokenIntrospectionResult)
            );
    }

    private Completable introspectAndValidateAccessToken(HttpExecutionContext ctx, String accessToken, OAuth2Resource<?> oauth2Resource) {
        return introspectAccessToken(ctx, accessToken, oauth2Resource)
            .flatMapCompletable(
                introspectionResult -> {
                    if (introspectionResult.isSuccess()) {
                        return validateOAuth2Payload(ctx, introspectionResult, oauth2Resource);
                    } else {
                        ctx.response().headers().add(HttpHeaderNames.WWW_AUTHENTICATE, BEARER_AUTHORIZATION_TYPE + " realm=gravitee.io ");

                        if (introspectionResult.getOauth2ResponseThrowable() == null) {
                            return ctx.interruptWith(
                                new ExecutionFailure(UNAUTHORIZED_401)
                                    .key(OAUTH2_INVALID_ACCESS_TOKEN_KEY)
                                    .message(introspectionResult.getOauth2ResponsePayload())
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

    /**
     * Get Oauth2 resource configured at policy level.
     *
     * @param ctx HttpExecutionContext
     * @return OAuth2Resource
     */
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

    /**
     * Get cache configured at policy level.
     *
     * @param ctx HttpExecutionContext
     * @return Cache
     */
    private Cache getPolicyTokenIntrospectionCache(HttpExecutionContext ctx) {
        if (oAuth2PolicyConfiguration.getOauthCacheResource() != null) {
            CacheResource cacheResource = ctx
                .getComponent(ResourceManager.class)
                .getResource(oAuth2PolicyConfiguration.getOauthCacheResource(), CacheResource.class);
            if (cacheResource != null) {
                return cacheResource.getCache(ctx);
            }
        }
        return null;
    }

    /**
     * Get token introspection cache from request context.
     *
     * @param ctx HttpExecutionContext
     * @return TokenIntrospectionCache
     */
    private TokenIntrospectionCache getContextTokenIntrospectionCache(HttpExecutionContext ctx) {
        TokenIntrospectionCache cache = ctx.getInternalAttribute(ATTR_INTERNAL_TOKEN_INTROSPECTIONS);
        if (cache == null) {
            cache = new TokenIntrospectionCache();
            ctx.setInternalAttribute(ATTR_INTERNAL_TOKEN_INTROSPECTIONS, cache);
        }
        return cache;
    }

    private static void fillTokenIntrospectionCache(
        String accessToken,
        OAuth2Resource<?> oauth2Resource,
        TokenIntrospectionCache tokenIntrospectionCache,
        Cache policyCache,
        TokenIntrospectionResult tokenIntrospectionResult
    ) {
        // put the introspection result in internal cache
        tokenIntrospectionCache.put(accessToken, oauth2Resource, tokenIntrospectionResult);

        // put the introspection result in policy cache if configured
        if (policyCache != null && tokenIntrospectionResult.isSuccess() && tokenIntrospectionResult.hasValidPayload()) {
            CacheElement element = new CacheElement(accessToken, tokenIntrospectionResult.getOauth2ResponsePayload());
            if (tokenIntrospectionResult.hasExpirationTime()) {
                long ttl = tokenIntrospectionResult.getExpirationTime() - System.currentTimeMillis() / 1000L;
                element.setTimeToLive(Long.valueOf(ttl).intValue());
            }
            policyCache.put(element);
        }
    }
}
