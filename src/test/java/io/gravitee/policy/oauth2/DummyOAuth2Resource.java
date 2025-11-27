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

import io.gravitee.gateway.api.handler.Handler;
import io.gravitee.resource.api.ResourceConfiguration;
import io.gravitee.resource.oauth2.api.OAuth2Resource;
import io.gravitee.resource.oauth2.api.OAuth2ResourceMetadata;
import io.gravitee.resource.oauth2.api.OAuth2Response;
import io.gravitee.resource.oauth2.api.openid.UserInfoResponse;
import java.util.List;

/**
 * @author GraviteeSource Team
 */
public class DummyOAuth2Resource extends OAuth2Resource<DummyOAuth2Resource.DummyOAuth2ResourceConfiguration> {

    public static String TOKEN_SUCCESS_WITH_CLIENT_ID = "my-test-token-1";
    public static String TOKEN_SUCCESS_WITHOUT_CLIENT_ID = "my-test-token-2";
    public static String TOKEN_SUCCESS_WITH_INVALID_PAYLOAD = "my-test-token-3";
    public static String TOKEN_FAIL = "my-test-token-4";

    public static String CLIENT_ID = "my-test-client-id";

    @Override
    public void introspect(String accessToken, Handler<OAuth2Response> responseHandler) {
        OAuth2Response response = null;

        if (TOKEN_SUCCESS_WITH_CLIENT_ID.equals(accessToken)) {
            response = new OAuth2Response(true, "{ \"client_id\": \"" + CLIENT_ID + "\"}");
        } else if (TOKEN_SUCCESS_WITHOUT_CLIENT_ID.equals(accessToken)) {
            response = new OAuth2Response(true, "{}");
        } else if (TOKEN_SUCCESS_WITH_INVALID_PAYLOAD.equals(accessToken)) {
            response = new OAuth2Response(true, "{this _is _invalid json");
        } else if (TOKEN_FAIL.equals(accessToken)) {
            response = new OAuth2Response(false, null);
        } else {
            response = new OAuth2Response(false, null);
        }

        responseHandler.handle(response);
    }

    @Override
    public void userInfo(String accessToken, Handler<UserInfoResponse> responseHandler) {}

    @Override
    public OAuth2ResourceMetadata getProtectedResourceMetadata(String protectedResourceUri) {
        return new OAuth2ResourceMetadata(protectedResourceUri, List.of("https://some.keycloak.com/realms/test"), List.of("read", "write"));
    }

    public static class DummyOAuth2ResourceConfiguration implements ResourceConfiguration {}
}
