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
import org.asynchttpclient.AsyncHandler;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.util.HashMap;
import java.util.UUID;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.mockito.internal.verification.VerificationModeFactory.times;

/**
 * @author Titouan COMPIEGNE (titouan.compiegne at gravitee.io)
 * @author GraviteeSource Team
 */
@RunWith(MockitoJUnitRunner.class)
public class OAuth2PolicyTest {

    @Mock
    Request mockRequest;

    @Mock
    Response mockResponse;

    @Mock
    ExecutionContext mockExecutionContext;

    @Mock
    PolicyChain mockPolicychain;

    @Mock
    OAuth2PolicyContext mockPolicyContext;

    @Mock
    HttpClient mockHttpClient;

    @Before
    public void init() {
        initMocks(this);
    }

    @Test
    public void shouldFailedIfNoAuthorizationHeaderProvided() {
        Oauth2Policy policy = new Oauth2Policy();
        when(mockResponse.headers()).thenReturn(new HttpHeaders());
        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);
        verify(mockPolicychain, times(1)).failWith(any(PolicyResult.class));
    }

    @Test
    public void shouldFailedIfNoAuthorizationHeaderBearerProvided() {
        final HttpHeaders headers = new HttpHeaders();
        headers.setAll(new HashMap<String, String>() {
            {
                put("Authorization", "Basic Test");
            }
        });

        Oauth2Policy policy = new Oauth2Policy();
        when(mockRequest.headers()).thenReturn(headers);
        when(mockResponse.headers()).thenReturn(new HttpHeaders());
        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);
        verify(mockPolicychain, times(1)).failWith(any(PolicyResult.class));
    }

    @Test
    public void shouldFailedIfNoAuthorizationAccessTokenBearerIsEmptyProvided() {
        final HttpHeaders headers = new HttpHeaders();
        headers.setAll(new HashMap<String, String>() {
            {
                put("Authorization", "Bearer");
            }
        });

        Oauth2Policy policy = new Oauth2Policy();
        when(mockRequest.headers()).thenReturn(headers);
        when(mockResponse.headers()).thenReturn(new HttpHeaders());
        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);
        verify(mockPolicychain, times(1)).failWith(any(PolicyResult.class));
    }

    @Test
    public void shouldCallOAuthAuthorizationServer() throws Exception {
        final HttpHeaders headers = new HttpHeaders();
        headers.setAll(new HashMap<String, String>() {
            {
                put("Authorization", "Bearer " + UUID.randomUUID().toString());
            }
        });

        Oauth2Policy policy = new Oauth2Policy();
        when(mockRequest.headers()).thenReturn(headers);
        when(mockResponse.headers()).thenReturn(new HttpHeaders());
        when(mockPolicyContext.getComponent(HttpClient.class)).thenReturn(mockHttpClient);
        policy.setPolicyContext(mockPolicyContext);
        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);
        verify(mockHttpClient, times(1)).validateToken(any(OAuth2Request.class), any(AsyncHandler.class));
    }

}
