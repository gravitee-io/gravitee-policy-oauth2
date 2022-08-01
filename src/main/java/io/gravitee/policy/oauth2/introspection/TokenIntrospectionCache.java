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
package io.gravitee.policy.oauth2.introspection;

import io.gravitee.resource.oauth2.api.OAuth2Resource;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Cache for token introspections.
 *
 * It caches token introspections results in request context, to avoid doing twice the same introspection.
 * Cache key is : introspected accessToken + oauth2 resource used for introspection.
 */
public class TokenIntrospectionCache {

    private Map<Integer, TokenIntrospectionResult> cache;

    public TokenIntrospectionCache() {
        cache = new HashMap<>();
    }

    public boolean contains(String accessToken, OAuth2Resource oAuth2Resource) {
        return cache.containsKey(buildCacheKey(accessToken, oAuth2Resource));
    }

    public Optional<TokenIntrospectionResult> get(String accessToken, OAuth2Resource oAuth2Resource) {
        return Optional.ofNullable(cache.get(buildCacheKey(accessToken, oAuth2Resource)));
    }

    public void put(String accessToken, OAuth2Resource oAuth2Resource, TokenIntrospectionResult tokenIntrospectionResult) {
        cache.put(buildCacheKey(accessToken, oAuth2Resource), tokenIntrospectionResult);
    }

    private Integer buildCacheKey(String accessToken, OAuth2Resource oAuth2Resource) {
        return Objects.hash(accessToken, oAuth2Resource);
    }
}
