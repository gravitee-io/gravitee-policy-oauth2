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
package io.gravitee.policy.oauth2.spring;

import io.gravitee.policy.oauth2.HttpClient;
import io.gravitee.policy.oauth2.OAuth2Request;
import org.asynchttpclient.*;

/**
 * @author Titouan COMPIEGNE (titouan.compiegne at gravitee.io)
 * @author GraviteeSource Team
 */
public class DefautHttpClient implements HttpClient {

    private AsyncHttpClient client;

    @Override
    public void init() throws Exception {
        client = new DefaultAsyncHttpClient();
    }

    @Override
    public void close() throws Exception {
        client.close();
    }

    @Override
    public void validateToken(OAuth2Request oAuth2Request, AsyncHandler responseHandler) {
        RequestBuilder builder = new RequestBuilder();
        builder.setUrl(oAuth2Request.getUrl());
        builder.setMethod(oAuth2Request.getMethod());
        builder.setHeaders(oAuth2Request.getHeaders());
        builder.setQueryParams(oAuth2Request.getQueryParams());

        Request request = builder.build();

        client.executeRequest(request, responseHandler);
    }
}