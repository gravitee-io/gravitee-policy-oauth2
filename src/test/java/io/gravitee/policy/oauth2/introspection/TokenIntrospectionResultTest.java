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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import io.gravitee.resource.oauth2.api.OAuth2Response;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class TokenIntrospectionResultTest {

    @Mock
    private OAuth2Response oAuth2Response;

    @Test
    public void should_contain_nothing_cause_Oauth2_response_is_not_success() {
        when(oAuth2Response.isSuccess()).thenReturn(false);

        TokenIntrospectionResult result = new TokenIntrospectionResult(oAuth2Response);

        assertFalse(result.isSuccess());
        assertFalse(result.hasValidPayload());
        assertFalse(result.hasClientId());
        assertFalse(result.hasExpirationTime());
        assertNull(result.getClientId());
        assertNull(result.getExpirationTime());
        assertNull(result.extractUser(null));
        assertEquals(0, result.extractScopes(",").size());
    }

    @Test
    public void should_contain_nothing_cause_Oauth2_response_payload_is_not_parseable() {
        when(oAuth2Response.isSuccess()).thenReturn(true);
        when(oAuth2Response.getPayload()).thenReturn("invalid - payload");

        TokenIntrospectionResult result = new TokenIntrospectionResult(oAuth2Response);

        assertTrue(result.isSuccess());
        assertFalse(result.hasValidPayload());
        assertFalse(result.hasClientId());
        assertFalse(result.hasExpirationTime());
        assertNull(result.getClientId());
        assertNull(result.getExpirationTime());
        assertNull(result.extractUser(null));
    }

    @Test
    public void should_contain_data_from_oauth2_response_payload() {
        when(oAuth2Response.isSuccess()).thenReturn(true);
        when(oAuth2Response.getPayload()).thenReturn(
            "{\"client_id\":\"my-test-client-id\", \"sub\":\"my-test-user\", \"exp\":\"123456789\"}"
        );

        TokenIntrospectionResult result = new TokenIntrospectionResult(oAuth2Response);

        assertTrue(result.isSuccess());
        assertTrue(result.hasValidPayload());
        assertTrue(result.hasClientId());
        assertTrue(result.hasExpirationTime());
        assertEquals("my-test-client-id", result.getClientId());
        assertEquals(123456789, result.getExpirationTime());
        assertEquals("my-test-user", result.extractUser(null));
    }

    static Stream<Arguments> clientIdFallbackToAud() {
        return Stream.of(
            Arguments.of("fallback to aud string when client_id is missing", "{\"aud\":\"my-aud-client-id\"}", "my-aud-client-id"),
            Arguments.of(
                "fallback to aud array first element when client_id is missing",
                "{\"aud\":[\"first-aud\",\"second-aud\"]}",
                "first-aud"
            ),
            Arguments.of("prefer client_id over aud", "{\"client_id\":\"my-client-id\", \"aud\":\"my-aud-client-id\"}", "my-client-id"),
            Arguments.of(
                "fallback to aud when client_id is empty",
                "{\"client_id\":\"\", \"aud\":\"my-aud-client-id\"}",
                "my-aud-client-id"
            )
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("clientIdFallbackToAud")
    void should_resolve_client_id_with_aud_fallback(String description, String payload, String expectedClientId) {
        when(oAuth2Response.isSuccess()).thenReturn(true);
        when(oAuth2Response.getPayload()).thenReturn(payload);

        TokenIntrospectionResult result = new TokenIntrospectionResult(oAuth2Response);

        assertTrue(result.hasClientId());
        assertEquals(expectedClientId, result.getClientId());
    }

    @Test
    public void should_extract_scopes_from_oauth2_response_payload_in_string() {
        when(oAuth2Response.isSuccess()).thenReturn(true);
        when(oAuth2Response.getPayload()).thenReturn("{\"scope\": \"my-test-scope1,my-test-scope2\"}");

        TokenIntrospectionResult result = new TokenIntrospectionResult(oAuth2Response);
        List<String> scopes = result.extractScopes(",");

        assertEquals(2, scopes.size());
        assertEquals("my-test-scope1", scopes.get(0));
        assertEquals("my-test-scope2", scopes.get(1));
    }

    @Test
    public void should_extract_scopes_from_oauth2_response_payload_in_array() {
        when(oAuth2Response.isSuccess()).thenReturn(true);
        when(oAuth2Response.getPayload()).thenReturn("{\"scope\": [\"my-test-scope1\",\"my-test-scope2\"]}");

        TokenIntrospectionResult result = new TokenIntrospectionResult(oAuth2Response);
        List<String> scopes = result.extractScopes(",");

        assertEquals(2, scopes.size());
        assertEquals("my-test-scope1", scopes.get(0));
        assertEquals("my-test-scope2", scopes.get(1));
    }
}
