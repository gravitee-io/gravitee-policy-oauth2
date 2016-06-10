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
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequest;
import io.gravitee.policy.oauth2.configuration.OAuth2PolicyConfiguration;
import io.gravitee.resource.api.ResourceManager;
import io.gravitee.resource.oauth2.OAuth2Request;
import io.gravitee.resource.oauth2.OAuth2Resource;
import io.gravitee.resource.oauth2.configuration.OAuth2ResourceConfiguration;
import org.asynchttpclient.AsyncCompletionHandler;
import org.asynchttpclient.AsyncHandler;

import javax.inject.Inject;
import java.util.*;

/**
 * @author David BRASSELY (david at gravitee.io)
 * @author GraviteeSource Team
 */
public class Oauth2Policy {

    private static final String BEARER_TYPE = "Bearer";
    private static final String OAUTH2_ACCESS_TOKEN = "OAUTH2_ACCESS_TOKEN";

    @Inject
    private OAuth2PolicyConfiguration oAuth2PolicyConfiguration;

    @OnRequest
    public void onRequest(Request request, Response response, ExecutionContext executionContext, PolicyChain policyChain) {
        if (request.headers() == null || request.headers().get(HttpHeaders.AUTHORIZATION) == null || request.headers().get(HttpHeaders.AUTHORIZATION).isEmpty()) {
            response.headers().add(HttpHeaders.WWW_AUTHENTICATE, BEARER_TYPE+" realm=gravitee.io - No OAuth authorization header was supplied");
            policyChain.failWith(PolicyResult.failure(401, "No OAuth authorization header was supplied"));
            return;
        }
        Optional<String> optionalHeaderAccessToken = request.headers().get(HttpHeaders.AUTHORIZATION).stream().filter(h -> h.startsWith("Bearer")).findFirst();

        if (!optionalHeaderAccessToken.isPresent()) {
            response.headers().add(HttpHeaders.WWW_AUTHENTICATE, BEARER_TYPE+" realm=gravitee.io - No OAuth authorization header was supplied");
            policyChain.failWith(PolicyResult.failure(401, "No OAuth authorization header was supplied"));
            return;
        }

        String accessToken = extractHeaderToken(optionalHeaderAccessToken.get());

        if (accessToken.isEmpty()) {
            response.headers().add(HttpHeaders.WWW_AUTHENTICATE, BEARER_TYPE+" realm=gravitee.io - No OAuth access token was supplied");
            policyChain.failWith(PolicyResult.failure(401, "No OAuth access token was supplied"));
            return;
        }

        OAuth2Resource oauth2 = executionContext.getComponent(ResourceManager.class).getResource("oauth2", OAuth2Resource.class);
        oauth2.validateToken(buildOAuthRequest(oauth2.configuration(), accessToken), responseHandler(policyChain, request, response, executionContext));
    }

    private String extractHeaderToken(String headerAccessToken) {
        return headerAccessToken.substring(BEARER_TYPE.length()).trim();
    }

    private OAuth2Request buildOAuthRequest(OAuth2ResourceConfiguration configuration, String accessToken) {
        Map<String, Collection<String>> headers = new HashMap<>();
        Map<String, List<String>> queryParams = new HashMap<>();

        OAuth2Request oAuth2Request = new OAuth2Request();

        oAuth2Request.setUrl(configuration.getServerURL());
        oAuth2Request.setMethod(configuration.getHttpMethod());

        if (configuration.isSecure()) {
            String headerName = configuration.getAuthorizationHeaderName();
            String headerValue = configuration.getAuthorizationScheme().trim() + " " + configuration.getAuthorizationValue();
            Collection<String> headerValues = Arrays.asList(new String[] { headerValue });
            headers.put(headerName, headerValues);
        }

        if (configuration.isTokenIsSuppliedByQueryParam()) {
            String queryParamName = configuration.getTokenQueryParamName();
            String queryParamValue = accessToken;
            List<String> queryParamValues = Arrays.asList(new String[] { queryParamValue });
            queryParams.put(queryParamName, queryParamValues);
        }

        if (configuration.isTokenIsSuppliedByHttpHeader()) {
            String headerName = configuration.getTokenHeaderName();
            String headerValue = accessToken;
            Collection<String> headerValues = Arrays.asList(new String[] { headerValue });
            headers.put(headerName, headerValues);
        }

        oAuth2Request.setHeaders(headers);
        oAuth2Request.setQueryParams(queryParams);

        return oAuth2Request;
    }

    private AsyncHandler responseHandler(PolicyChain policyChain, Request request, Response response, ExecutionContext executionContext) {
        return new AsyncCompletionHandler<Void>() {

            @Override
            public Void onCompleted(org.asynchttpclient.Response clientResponse) throws Exception {
                if (clientResponse.getStatusCode() == 200) {
                    executionContext.setAttribute(OAUTH2_ACCESS_TOKEN, clientResponse.getResponseBody());
                    policyChain.doNext(request, response);
                } else {
                    response.headers().add(HttpHeaders.WWW_AUTHENTICATE, BEARER_TYPE+" realm=gravitee.io " + clientResponse.getResponseBody());
                    policyChain.failWith(PolicyResult.failure(401, clientResponse.getResponseBody()));
                }
                return null;
            }

            @Override
            public void onThrowable(Throwable t) {
                super.onThrowable(t);
                response.headers().add(HttpHeaders.WWW_AUTHENTICATE, BEARER_TYPE + " realm=gravitee.io " + t.getMessage());
                policyChain.failWith(PolicyResult.failure(t.getMessage()));
            }
        };
    }
}
