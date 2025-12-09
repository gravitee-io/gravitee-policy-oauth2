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

import static io.gravitee.common.http.HttpStatusCode.SERVICE_UNAVAILABLE_503;
import static io.gravitee.common.http.HttpStatusCode.UNAUTHORIZED_401;
import static io.gravitee.gateway.api.ExecutionContext.ATTR_USER;
import static io.gravitee.gateway.api.ExecutionContext.ATTR_USER_ROLES;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.gravitee.common.security.jwt.LazyJWT;
import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.gateway.api.http.HttpHeaderNames;
import io.gravitee.gateway.reactive.api.ExecutionFailure;
import io.gravitee.gateway.reactive.api.context.InternalContextAttributes;
import io.gravitee.gateway.reactive.api.context.base.BaseExecutionContext;
import io.gravitee.gateway.reactive.api.context.http.HttpPlainExecutionContext;
import io.gravitee.gateway.reactive.api.context.http.HttpPlainRequest;
import io.gravitee.gateway.reactive.api.context.kafka.KafkaConnectionContext;
import io.gravitee.gateway.reactive.api.policy.SecurityToken;
import io.gravitee.gateway.reactive.api.policy.http.HttpSecurityPolicy;
import io.gravitee.gateway.reactive.api.policy.kafka.KafkaSecurityPolicy;
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
import io.gravitee.resource.oauth2.api.OAuth2ResourceMetadata;
import io.gravitee.resource.oauth2.api.OAuth2Response;
import io.reactivex.rxjava3.core.Completable;
import io.reactivex.rxjava3.core.Maybe;
import io.reactivex.rxjava3.core.Single;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import javax.security.auth.callback.Callback;
import lombok.Getter;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerValidatorCallback;
import org.apache.kafka.common.security.oauthbearer.internals.secured.BasicOAuthBearerToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
@RequireResource
public class Oauth2Policy extends Oauth2PolicyV3 implements HttpSecurityPolicy, KafkaSecurityPolicy {

    public static final String CONTEXT_ATTRIBUTE_JWT = "jwt";
    public static final String CONTEXT_ATTRIBUTE_TOKEN = CONTEXT_ATTRIBUTE_PREFIX + "token";

    public static final String ATTR_INTERNAL_TOKEN_INTROSPECTIONS = "token-introspection-cache";
    public static final String ATTR_INTERNAL_TOKEN_INTROSPECTION_RESULT = "token-introspection-result";

    private static final String KAFKA_OAUTHBEARER_MAX_TOKEN_LIFETIME = "kafka.oauthbearer.maxTokenLifetime";
    private static final long DEFAULT_MAX_TOKEN_LIFETIME_MS = 60 * 60 * 1000L; // 1 hour

    private static final Logger log = LoggerFactory.getLogger(Oauth2Policy.class);

    private enum Oauth2Failure {
        OAUTH2_MISSING_SERVER_FAILURE(UNAUTHORIZED_401, OAUTH2_MISSING_SERVER_KEY, OAUTH2_UNAUTHORIZED_MESSAGE, false),
        OAUTH2_MISSING_HEADER_FAILURE(UNAUTHORIZED_401, OAUTH2_MISSING_HEADER_KEY, OAUTH2_UNAUTHORIZED_MESSAGE, true),
        OAUTH2_MISSING_ACCESS_TOKEN_FAILURE(UNAUTHORIZED_401, OAUTH2_MISSING_ACCESS_TOKEN_KEY, OAUTH2_UNAUTHORIZED_MESSAGE, true),
        OAUTH2_INVALID_ACCESS_TOKEN_FAILURE(UNAUTHORIZED_401, OAUTH2_INVALID_ACCESS_TOKEN_KEY, OAUTH2_UNAUTHORIZED_MESSAGE, true),
        OAUTH2_INVALID_SERVER_RESPONSE_FAILURE(UNAUTHORIZED_401, OAUTH2_INVALID_SERVER_RESPONSE_KEY, OAUTH2_UNAUTHORIZED_MESSAGE, true),
        OAUTH2_INSUFFICIENT_SCOPE_FAILURE(UNAUTHORIZED_401, OAUTH2_INSUFFICIENT_SCOPE_KEY, OAUTH2_UNAUTHORIZED_MESSAGE, true),
        OAUTH2_SERVER_UNAVAILABLE_FAILURE(
            SERVICE_UNAVAILABLE_503,
            OAUTH2_SERVER_UNAVAILABLE_KEY,
            OAUTH2_TEMPORARILY_UNAVAILABLE_MESSAGE,
            true
        );

        private final int httpStatusCode;

        @Getter
        private final String failureKey;

        private final String failureMessage;

        @Getter
        private final boolean addWWWAuthenticateHeader;

        Oauth2Failure(int httpStatusCode, String failureKey, String failureMessage, boolean addWWWAuthenticateHeader) {
            this.httpStatusCode = httpStatusCode;
            this.failureKey = failureKey;
            this.failureMessage = failureMessage;
            this.addWWWAuthenticateHeader = addWWWAuthenticateHeader;
        }

        public ExecutionFailure toExecutionFailure() {
            return new ExecutionFailure(httpStatusCode).key(failureKey).message(failureMessage);
        }
    }

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
    public boolean requireSubscription(BaseExecutionContext context) {
        return "MCP_PROXY".equals(context.getInternalAttribute(InternalContextAttributes.ATTR_INTERNAL_API_TYPE));
    }

    @Override
    public Maybe<SecurityToken> extractSecurityToken(HttpPlainExecutionContext ctx) {
        return getSecurityTokenFromContext(ctx);
    }

    @Override
    public Maybe<SecurityToken> extractSecurityToken(KafkaConnectionContext ctx) {
        return getSecurityTokenFromContext(ctx);
    }

    @Override
    public Completable onRequest(final HttpPlainExecutionContext ctx) {
        return Completable.defer(() -> {
            log.debug("Read access_token from request {}", ctx.request().id());
            return handleSecurity(ctx);
        })
            .andThen(
                Completable.fromRunnable(() -> {
                    ctx.metrics().setUser(ctx.getAttribute(ATTR_USER));
                    if (!oAuth2PolicyConfiguration.isPropagateAuthHeader()) {
                        ctx.request().headers().remove(HttpHeaderNames.AUTHORIZATION);
                    }
                })
            )
            .doAfterTerminate(() -> ctx.removeInternalAttribute(ATTR_INTERNAL_TOKEN_INTROSPECTION_RESULT));
    }

    @Override
    public Completable authenticate(KafkaConnectionContext ctx) {
        return handleSecurity(ctx)
            .andThen(
                Completable.fromRunnable(() -> {
                    Callback[] callbacks = ctx.callbacks();
                    for (Callback callback : callbacks) {
                        if (callback instanceof OAuthBearerValidatorCallback oauthCallback) {
                            String extractedToken = ctx.getAttribute(CONTEXT_ATTRIBUTE_TOKEN);
                            String user = ctx.getAttribute(ATTR_USER);
                            TokenIntrospectionResult tokenIntrospectionResult = ctx.getInternalAttribute(
                                ATTR_INTERNAL_TOKEN_INTROSPECTION_RESULT
                            );

                            Long expirationTime = tokenIntrospectionResult.getExpirationTime();
                            Long issueTime = tokenIntrospectionResult.getIssuedAtTime();

                            Environment environment = ctx.getComponent(Environment.class);
                            long maxTokenLifetime = environment.getProperty(
                                KAFKA_OAUTHBEARER_MAX_TOKEN_LIFETIME,
                                Long.class,
                                DEFAULT_MAX_TOKEN_LIFETIME_MS
                            );

                            OAuthBearerToken token = new BasicOAuthBearerToken(
                                extractedToken,
                                Set.of(), // Scopes are fully managed by Gravitee, it is useless to extract & provide them to the Kafka security context.
                                (expirationTime == null ? maxTokenLifetime : Math.min(maxTokenLifetime, expirationTime * 1000)),
                                user != null ? user : "unknown",
                                issueTime
                            );

                            oauthCallback.token(token);
                        }
                    }
                })
            )
            .onErrorResumeNext(throwable -> {
                Callback[] callbacks = ctx.callbacks();
                for (Callback callback : callbacks) {
                    if (callback instanceof OAuthBearerValidatorCallback oauthCallback) {
                        oauthCallback.error("invalid_token", null, null);
                    }
                }
                return Completable.complete();
            })
            .doAfterTerminate(() -> ctx.removeInternalAttribute(ATTR_INTERNAL_TOKEN_INTROSPECTION_RESULT));
    }

    @Override
    public Single<Boolean> wwwAuthenticate(final HttpPlainExecutionContext ctx) {
        if (oAuth2PolicyConfiguration.isAddWwwAuthenticateHeader()) {
            String resourceMetadata = contextPathUrl(ctx.request()) + ".well-known/oauth-protected-resource";
            ctx.response().headers().set(HttpHeaderNames.WWW_AUTHENTICATE, "Bearer resource_metadata=\"" + resourceMetadata + "\"");
            return Single.just(true);
        }
        return Single.just(false);
    }

    static String contextPathUrl(HttpPlainRequest request) {
        String url = request.scheme() + "://" + request.originalHost();
        if (request.contextPath().endsWith("/")) {
            return url + request.contextPath();
        } else {
            return url + request.contextPath() + "/";
        }
    }

    @Override
    public Single<Boolean> onWellKnown(final HttpPlainExecutionContext ctx) {
        if (ctx.request().path().endsWith(".well-known/oauth-protected-resource")) {
            final OAuth2Resource<?> oauth2Resource = getOauth2Resource(ctx);
            String protectedResourceUri = contextPathUrl(ctx.request());
            protectedResourceUri = protectedResourceUri.endsWith("/")
                ? protectedResourceUri.substring(0, protectedResourceUri.length() - 1)
                : protectedResourceUri;
            OAuth2ResourceMetadata resourceMetadata = oauth2Resource.getProtectedResourceMetadata(protectedResourceUri);
            try {
                String message = MAPPER.writeValueAsString(resourceMetadata);
                ctx.response().body(Buffer.buffer(message));
                return Single.just(true);
            } catch (JsonProcessingException e) {
                log.error("Unable to serialize OAuth2 resource metadata", e);
                return Single.just(false);
            }
        }
        return Single.just(false);
    }

    private Maybe<SecurityToken> getSecurityTokenFromContext(BaseExecutionContext ctx) {
        final OAuth2Resource<?> oauth2Resource = getOauth2Resource(ctx);
        if (oauth2Resource == null) {
            log.debug("Skipping security token extraction cause no oauth2 resource configured");
            return Maybe.empty();
        }

        return fetchJWTToken(ctx, true)
            .flatMap(token -> introspectAccessToken(ctx, token, oauth2Resource).toMaybe())
            .flatMap(introspectionResult -> {
                if (introspectionResult.hasClientId()) {
                    return Maybe.just(SecurityToken.forClientId(introspectionResult.getClientId()));
                }
                if (introspectionResult.getOauth2ResponseThrowable() != null) {
                    return Maybe.error(introspectionResult.getOauth2ResponseThrowable());
                }
                return Maybe.just(SecurityToken.invalid(SecurityToken.TokenType.CLIENT_ID));
            });
    }

    private Completable handleSecurity(final BaseExecutionContext ctx) {
        final OAuth2Resource<?> oauth2Resource = getOauth2Resource(ctx);

        if (oauth2Resource == null) {
            return interruptWith(ctx, Oauth2Failure.OAUTH2_MISSING_SERVER_FAILURE);
        }

        return fetchJWTToken(ctx, false)
            .switchIfEmpty(Maybe.defer(() -> interruptWith(ctx, Oauth2Failure.OAUTH2_MISSING_HEADER_FAILURE).toMaybe()))
            .flatMapCompletable(accessToken -> {
                if (accessToken.isBlank()) {
                    return interruptWith(ctx, Oauth2Failure.OAUTH2_MISSING_ACCESS_TOKEN_FAILURE);
                }

                // Set access_token in context
                ctx.setAttribute(CONTEXT_ATTRIBUTE_OAUTH_ACCESS_TOKEN, accessToken);

                // Introspect and validate access token
                return introspectAndValidateAccessToken(ctx, accessToken, oauth2Resource);
            });
    }

    /**
     * Extract JWT token from request execution context.
     * Returns empty if no token found.
     *
     * @param ctx request execution context.
     * @param canUseCache allow retrieval of a previously extracted token from the request context cache
     * @return JWT token, or empty if no token found.
     */
    private Maybe<String> fetchJWTToken(BaseExecutionContext ctx, boolean canUseCache) {
        return Maybe.defer(() -> {
            LazyJWT jwt = canUseCache ? ctx.getAttribute(CONTEXT_ATTRIBUTE_JWT) : null;
            if (jwt == null) {
                Optional<String> token = TokenExtractor.extract(ctx);
                if (token.isEmpty()) {
                    return Maybe.empty();
                }
                jwt = new LazyJWT(token.get());
                ctx.setAttribute(CONTEXT_ATTRIBUTE_JWT, jwt);
            }
            return Maybe.just(jwt.getToken());
        }).doOnSuccess(token -> ctx.setAttribute(CONTEXT_ATTRIBUTE_TOKEN, token));
    }

    private Completable validateOAuth2Payload(
        BaseExecutionContext ctx,
        TokenIntrospectionResult tokenIntrospectionResult,
        OAuth2Resource<?> oauth2Resource
    ) {
        if (!tokenIntrospectionResult.hasValidPayload()) {
            return interruptWith(ctx, Oauth2Failure.OAUTH2_INVALID_SERVER_RESPONSE_FAILURE);
        }

        if (tokenIntrospectionResult.hasClientId()) {
            ctx.setAttribute(CONTEXT_ATTRIBUTE_CLIENT_ID, tokenIntrospectionResult.getClientId());
        }

        String user = tokenIntrospectionResult.extractUser(oauth2Resource.getUserClaim());
        if (user != null && !user.trim().isEmpty()) {
            ctx.setAttribute(ATTR_USER, user);
        }

        List<String> scopes = tokenIntrospectionResult.extractScopes(oauth2Resource.getScopeSeparator());
        ctx.setAttribute(ATTR_USER_ROLES, scopes);

        // Check required scopes to access the resource
        if (oAuth2PolicyConfiguration.isCheckRequiredScopes()) {
            if (!hasRequiredScopes(scopes, oAuth2PolicyConfiguration.getRequiredScopes(), oAuth2PolicyConfiguration.isModeStrict())) {
                return interruptWith(ctx, Oauth2Failure.OAUTH2_INSUFFICIENT_SCOPE_FAILURE);
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
        BaseExecutionContext ctx,
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
            .doOnSuccess(tokenIntrospectionResult ->
                fillTokenIntrospectionCache(accessToken, oauth2Resource, tokenIntrospectionCache, policyCache, tokenIntrospectionResult)
            );
    }

    private Completable introspectAndValidateAccessToken(BaseExecutionContext ctx, String accessToken, OAuth2Resource<?> oauth2Resource) {
        return introspectAccessToken(ctx, accessToken, oauth2Resource).flatMapCompletable(introspectionResult -> {
            ctx.setInternalAttribute(ATTR_INTERNAL_TOKEN_INTROSPECTION_RESULT, introspectionResult);
            if (introspectionResult.isSuccess()) {
                return validateOAuth2Payload(ctx, introspectionResult, oauth2Resource);
            } else {
                if (introspectionResult.getOauth2ResponseThrowable() == null) {
                    return interruptWith(ctx, Oauth2Failure.OAUTH2_INVALID_ACCESS_TOKEN_FAILURE);
                } else {
                    return interruptWith(ctx, Oauth2Failure.OAUTH2_SERVER_UNAVAILABLE_FAILURE);
                }
            }
        });
    }

    /**
     * As per https://tools.ietf.org/html/rfc6750#page-7:
     *
     *      HTTP/1.1 401 Unauthorized
     *      WWW-Authenticate: Bearer realm="example",
     *      error="invalid_token",
     *      error_description="The access token expired"
     */
    private Completable interruptWith(BaseExecutionContext ctx, Oauth2Failure failure) {
        if (ctx instanceof HttpPlainExecutionContext httpPlainExecutionContext) {
            if (failure.isAddWWWAuthenticateHeader()) {
                String headerValue = BEARER_AUTHORIZATION_TYPE + " realm=\"gravitee.io\"";
                httpPlainExecutionContext.response().headers().add(HttpHeaderNames.WWW_AUTHENTICATE, headerValue);
            }
            return httpPlainExecutionContext.interruptWith(failure.toExecutionFailure());
        }
        // FIXME: Kafka Gateway - manage interruption with Kafka.
        return Completable.error(new Exception(failure.getFailureKey()));
    }

    /**
     * Get Oauth2 resource configured at policy level.
     *
     * @param ctx HttpPlainExecutionContext
     * @return OAuth2Resource
     */
    private OAuth2Resource<?> getOauth2Resource(BaseExecutionContext ctx) {
        if (oAuth2PolicyConfiguration.getOauthResource() == null) {
            return null;
        }

        return ctx
            .getComponent(ResourceManager.class)
            .getResource(ctx.getTemplateEngine().evalNow(oAuth2PolicyConfiguration.getOauthResource(), String.class), OAuth2Resource.class);
    }

    /**
     * Get cache configured at policy level.
     *
     * @param ctx HttpPlainExecutionContext
     * @return Cache
     */
    private Cache getPolicyTokenIntrospectionCache(BaseExecutionContext ctx) {
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
     * @param ctx HttpPlainExecutionContext
     * @return TokenIntrospectionCache
     */
    private TokenIntrospectionCache getContextTokenIntrospectionCache(BaseExecutionContext ctx) {
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
