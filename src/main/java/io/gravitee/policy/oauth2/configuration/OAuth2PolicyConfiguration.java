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
package io.gravitee.policy.oauth2.configuration;

import io.gravitee.policy.api.PolicyConfiguration;
import java.util.ArrayList;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class OAuth2PolicyConfiguration implements PolicyConfiguration {

    private String oauthResource;
    private String oauthCacheResource;
    private boolean extractPayload = false;
    private boolean checkRequiredScopes = false;
    private List<String> requiredScopes = new ArrayList<>();
    private boolean modeStrict = true;

    private ConfirmationMethodValidation confirmationMethodValidation = new ConfirmationMethodValidation();

    private boolean propagateAuthHeader = true;

    @NoArgsConstructor
    @AllArgsConstructor
    @Getter
    @Setter
    public static class ConfirmationMethodValidation {

        private boolean ignoreMissing = false;
        private CertificateBoundThumbprint certificateBoundThumbprint = new CertificateBoundThumbprint();
    }

    @NoArgsConstructor
    @AllArgsConstructor
    @Getter
    @Setter
    public static class CertificateBoundThumbprint {

        private boolean enabled = false;
        private boolean extractCertificateFromHeader = false;
        private String headerName = "ssl-client-cert";
    }
}
