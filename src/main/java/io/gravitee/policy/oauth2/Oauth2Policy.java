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

import io.gravitee.common.http.HttpHeaders;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.common.http.MediaType;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.handler.Handler;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequest;
import io.gravitee.policy.oauth2.configuration.OAuth2PolicyConfiguration;
import io.gravitee.resource.api.ResourceManager;
import io.gravitee.resource.oauth2.api.OAuth2Resource;
import io.gravitee.resource.oauth2.api.OAuth2Response;

import java.util.Optional;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
public class Oauth2Policy {

    private static final String BEARER_TYPE = "Bearer";
    static final String CONTEXT_ATTRIBUTE_OAUTH_PAYLOAD = "oauth.payload";
    static final String CONTEXT_ATTRIBUTE_OAUTH_ACCESS_TOKEN = "oauth.access_token";

    private OAuth2PolicyConfiguration oAuth2PolicyConfiguration;

    public Oauth2Policy (OAuth2PolicyConfiguration oAuth2PolicyConfiguration) {
        this.oAuth2PolicyConfiguration = oAuth2PolicyConfiguration;
    }

    @OnRequest
    public void onRequest(Request request, Response response, ExecutionContext executionContext, PolicyChain policyChain) {
        OAuth2Resource oauth2 = executionContext.getComponent(ResourceManager.class).getResource(
                oAuth2PolicyConfiguration.getOauthResource(), OAuth2Resource.class);

        if (oauth2 == null) {
            policyChain.failWith(PolicyResult.failure(HttpStatusCode.UNAUTHORIZED_401,
                    "No OAuth authorization server has been configured"));
            return;
        }

        if (request.headers() == null || request.headers().get(HttpHeaders.AUTHORIZATION) == null || request.headers().get(HttpHeaders.AUTHORIZATION).isEmpty()) {
            response.headers().add(HttpHeaders.WWW_AUTHENTICATE, BEARER_TYPE+" realm=gravitee.io - No OAuth authorization header was supplied");
            policyChain.failWith(PolicyResult.failure(HttpStatusCode.UNAUTHORIZED_401,
                    "No OAuth authorization header was supplied"));
            return;
        }

        Optional<String> optionalHeaderAccessToken = request.headers().get(HttpHeaders.AUTHORIZATION).stream().filter(h -> h.startsWith("Bearer")).findFirst();
        if (!optionalHeaderAccessToken.isPresent()) {
            response.headers().add(HttpHeaders.WWW_AUTHENTICATE, BEARER_TYPE+" realm=gravitee.io - No OAuth authorization header was supplied");
            policyChain.failWith(PolicyResult.failure(HttpStatusCode.UNAUTHORIZED_401,
                    "No OAuth authorization header was supplied"));
            return;
        }

        String accessToken = optionalHeaderAccessToken.get().substring(BEARER_TYPE.length()).trim();
        if (accessToken.isEmpty()) {
            response.headers().add(HttpHeaders.WWW_AUTHENTICATE, BEARER_TYPE+" realm=gravitee.io - No OAuth access token was supplied");
            policyChain.failWith(PolicyResult.failure(HttpStatusCode.UNAUTHORIZED_401,
                    "No OAuth access token was supplied"));
            return;
        }

        // Set access_token in context
        executionContext.setAttribute(CONTEXT_ATTRIBUTE_OAUTH_ACCESS_TOKEN, accessToken);

        // Validate access token
        oauth2.introspect(accessToken, handleResponse(policyChain, request, response, executionContext));
    }

    private Handler<OAuth2Response> handleResponse(PolicyChain policyChain, Request request, Response response, ExecutionContext executionContext) {
        return oauth2response -> {
            if (oauth2response.isSuccess()) {
                if (oAuth2PolicyConfiguration.isExtractPayload()) {
                    executionContext.setAttribute(CONTEXT_ATTRIBUTE_OAUTH_PAYLOAD, oauth2response.getPayload());
                }
                policyChain.doNext(request, response);
            } else {
                response.headers().add(HttpHeaders.WWW_AUTHENTICATE, BEARER_TYPE+" realm=gravitee.io " + oauth2response.getPayload());

                if (oauth2response.getThrowable() == null) {
                    policyChain.failWith(PolicyResult.failure(HttpStatusCode.UNAUTHORIZED_401,
                            oauth2response.getPayload(), MediaType.APPLICATION_JSON));
                } else {
                    policyChain.failWith(PolicyResult.failure(HttpStatusCode.SERVICE_UNAVAILABLE_503,
                            "Service Unavailable"));
                }
            }
        };
    }
}
