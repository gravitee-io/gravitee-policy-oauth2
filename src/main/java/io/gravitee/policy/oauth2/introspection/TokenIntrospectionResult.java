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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import io.gravitee.policy.oauth2.Oauth2Policy;
import io.gravitee.resource.oauth2.api.OAuth2Response;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The result of an Oauth2 token introspection.
 */
public class TokenIntrospectionResult {

    private static final Logger LOGGER = LoggerFactory.getLogger(Oauth2Policy.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    public static final String OAUTH_PAYLOAD_SCOPE_NODE = "scope";
    public static final String OAUTH_PAYLOAD_SCOPE_NODE_LEGACY = "scp";
    public static final String OAUTH_PAYLOAD_CLIENT_ID_NODE = "client_id";
    public static final String OAUTH_PAYLOAD_SUB_NODE = "sub";
    public static final String OAUTH_PAYLOAD_EXP = "exp";

    private String oauth2ResponsePayload;
    private boolean success;
    private JsonNode oAuth2ResponseJsonNode;
    private Throwable oauth2ResponseThrowable;

    public TokenIntrospectionResult(OAuth2Response oAuth2Response) {
        this.success = oAuth2Response.isSuccess();
        this.oauth2ResponsePayload = oAuth2Response.getPayload();
        this.oauth2ResponseThrowable = oAuth2Response.getThrowable();
        this.oAuth2ResponseJsonNode = readPayload();
    }

    public TokenIntrospectionResult(String oauth2ResponsePayload) {
        this.success = true;
        this.oauth2ResponsePayload = oauth2ResponsePayload;
        this.oAuth2ResponseJsonNode = readPayload();
    }

    public String getClientId() {
        if (hasValidPayload()) {
            return oAuth2ResponseJsonNode.path(OAUTH_PAYLOAD_CLIENT_ID_NODE).asText();
        }
        return null;
    }

    public boolean hasClientId() {
        return getClientId() != null && !getClientId().isBlank();
    }

    public Long getExpirationTime() {
        if (hasValidPayload() && oAuth2ResponseJsonNode.has(OAUTH_PAYLOAD_EXP)) {
            return oAuth2ResponseJsonNode.get(OAUTH_PAYLOAD_EXP).asLong();
        }
        return null;
    }

    public boolean hasExpirationTime() {
        return getExpirationTime() != null;
    }

    public List<String> extractScopes(String scopeSeparator) {
        if (hasValidPayload()) {
            JsonNode scopesNode = oAuth2ResponseJsonNode.path(OAUTH_PAYLOAD_SCOPE_NODE);
            if (scopesNode.isMissingNode()) {
                scopesNode = oAuth2ResponseJsonNode.path(OAUTH_PAYLOAD_SCOPE_NODE_LEGACY);
            }
            List<String> scopes;
            if (scopesNode instanceof ArrayNode) {
                Iterator<JsonNode> scopeIterator = scopesNode.elements();
                scopes = new ArrayList<>(scopesNode.size());
                scopeIterator.forEachRemaining(jsonNode -> scopes.add(jsonNode.asText()));
            } else {
                scopes = Arrays.asList(scopesNode.asText().split(scopeSeparator));
            }
            return scopes;
        }
        return new ArrayList<>();
    }

    public String extractUser(String userClaim) {
        if (hasValidPayload()) {
            return oAuth2ResponseJsonNode.path(userClaim == null ? OAUTH_PAYLOAD_SUB_NODE : userClaim).asText();
        }
        return null;
    }

    private JsonNode readPayload(String payload) {
        try {
            return MAPPER.readTree(payload);
        } catch (IOException ioe) {
            LOGGER.error("Unable to read Oauth2 token payload : {}", payload);
            return null;
        }
    }

    private JsonNode readPayload() {
        if (success && oauth2ResponsePayload != null) {
            return readPayload(oauth2ResponsePayload);
        }
        return null;
    }

    public boolean hasValidPayload() {
        return oAuth2ResponseJsonNode != null;
    }

    public String getOauth2ResponsePayload() {
        return oauth2ResponsePayload;
    }

    public Throwable getOauth2ResponseThrowable() {
        return oauth2ResponseThrowable;
    }

    public boolean isSuccess() {
        return success;
    }
}
