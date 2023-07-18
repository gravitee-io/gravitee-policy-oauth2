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
package io.gravitee.policy.oauth2.introspection;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

import io.gravitee.resource.oauth2.api.OAuth2Resource;
import java.util.Optional;
import org.junit.jupiter.api.Test;

public class TokenIntrospectionCacheTest {

    private static final String ACCESS_TOKEN = "test-access-token";
    private static final OAuth2Resource OAUTH2_RESOURCE = mock(OAuth2Resource.class);
    private static final TokenIntrospectionResult INTROSPECTION_RESULT = mock(TokenIntrospectionResult.class);

    private TokenIntrospectionCache cache = new TokenIntrospectionCache();

    @Test
    public void get_should_return_empty() {
        Optional<TokenIntrospectionResult> result = cache.get(ACCESS_TOKEN, OAUTH2_RESOURCE);
        assertTrue(result.isEmpty());
    }

    @Test
    public void contains_should_return_false() {
        boolean result = cache.contains(ACCESS_TOKEN, OAUTH2_RESOURCE);
        assertFalse(result);
    }

    @Test
    public void put_then_get_should_return_result() {
        cache.put(ACCESS_TOKEN, OAUTH2_RESOURCE, INTROSPECTION_RESULT);

        Optional<TokenIntrospectionResult> result = cache.get(ACCESS_TOKEN, OAUTH2_RESOURCE);

        assertTrue(result.isPresent());
        assertSame(result.get(), INTROSPECTION_RESULT);
    }

    @Test
    public void put_then_contains_should_return_true() {
        cache.put(ACCESS_TOKEN, OAUTH2_RESOURCE, INTROSPECTION_RESULT);

        boolean result = cache.contains(ACCESS_TOKEN, OAUTH2_RESOURCE);

        assertTrue(result);
    }
}
