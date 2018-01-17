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
package io.gravitee.policy.oauth2.configuration;

import io.gravitee.policy.api.PolicyConfiguration;

import java.util.ArrayList;
import java.util.List;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class OAuth2PolicyConfiguration implements PolicyConfiguration {

    private String oauthResource;

    private boolean extractPayload = false;

    private boolean checkRequiredScopes = false;

    private List<String> requiredScopes = new ArrayList<>();

    private String scopeDelimiter = " ";

    public String getOauthResource() {
        return oauthResource;
    }

    public void setOauthResource(String oauthResource) {
        this.oauthResource = oauthResource;
    }

    public boolean isExtractPayload() {
        return extractPayload;
    }

    public void setExtractPayload(boolean extractPayload) {
        this.extractPayload = extractPayload;
    }

    public boolean isCheckRequiredScopes() {
        return checkRequiredScopes;
    }

    public void setCheckRequiredScopes(boolean checkRequiredScopes) {
        this.checkRequiredScopes = checkRequiredScopes;
    }

    public List<String> getRequiredScopes() {
        return requiredScopes;
    }

    public void setRequiredScopes(List<String> requiredScopes) {
        this.requiredScopes = requiredScopes;
    }

    public String getScopeDelimiter() {
        return scopeDelimiter;
    }

    public void setScopeDelimiter(String scopeDelimiter) {
        this.scopeDelimiter = scopeDelimiter;
    }
}
