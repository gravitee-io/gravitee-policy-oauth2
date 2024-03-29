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
package io.gravitee.policy.oauth2.utils;

import static org.mockito.Mockito.when;

import io.gravitee.common.util.LinkedMultiValueMap;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.http.HttpHeaders;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
@ExtendWith(MockitoExtension.class)
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
public class TokenExtractorTest {

    @Mock
    private Request request;

    @Test
    void should_not_extract_with__no_authorization_header() {
        when(request.headers()).thenReturn(HttpHeaders.create());
        when(request.parameters()).thenReturn(new LinkedMultiValueMap<>());

        String token = TokenExtractor.extract(request);

        Assertions.assertNull(token);
    }

    @Test
    void should_not_extract_with_unknown_authorization_header() {
        String jwt = "dummy-token";

        HttpHeaders headers = HttpHeaders.create().set("Authorization", "Basic " + jwt);
        when(request.headers()).thenReturn(headers);

        String token = TokenExtractor.extract(request);
        Assertions.assertNull(token);
    }

    @Test
    void should_extract_with_authorization_header_and_empty_bearer() {
        HttpHeaders headers = HttpHeaders.create().set("Authorization", TokenExtractor.BEARER);
        when(request.headers()).thenReturn(headers);

        String token = TokenExtractor.extract(request);
        Assertions.assertNotNull(token);
        Assertions.assertEquals("", token);
    }

    @Test
    void should_extract_with_authorization_header_and_bearer() {
        String jwt = "dummy-token";

        HttpHeaders headers = HttpHeaders.create().set("Authorization", TokenExtractor.BEARER + ' ' + jwt);
        when(request.headers()).thenReturn(headers);

        String token = TokenExtractor.extract(request);

        Assertions.assertNotNull(token);
        Assertions.assertEquals(jwt, token);
    }

    @Test
    void should_extract_from_insensitive_header() {
        String jwt = "dummy-token";

        HttpHeaders headers = HttpHeaders.create().set("Authorization", "bearer " + jwt);
        when(request.headers()).thenReturn(headers);

        String token = TokenExtractor.extract(request);

        Assertions.assertNotNull(token);
        Assertions.assertEquals(jwt, token);
    }

    @Test
    void should_extract_from_query_parameter() {
        String jwt = "dummy-token";

        when(request.headers()).thenReturn(HttpHeaders.create());

        LinkedMultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add(TokenExtractor.ACCESS_TOKEN, jwt);
        when(request.parameters()).thenReturn(parameters);

        String token = TokenExtractor.extract(request);

        Assertions.assertNotNull(token);
        Assertions.assertEquals(jwt, token);
    }

    @Test
    void should_extract_from_empty_query_parameter() {
        when(request.headers()).thenReturn(HttpHeaders.create());

        LinkedMultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add(TokenExtractor.ACCESS_TOKEN, "");
        when(request.parameters()).thenReturn(parameters);

        String token = TokenExtractor.extract(request);

        Assertions.assertNotNull(token);
        Assertions.assertEquals("", token);
    }
}
