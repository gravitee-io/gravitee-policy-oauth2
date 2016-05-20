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
import io.gravitee.policy.api.PolicyContext;
import io.gravitee.policy.api.PolicyContextProvider;
import io.gravitee.policy.api.PolicyContextProviderAware;
import io.gravitee.policy.api.annotations.properties.Property;
import io.gravitee.policy.oauth2.spring.Oauth2Configuration;
import org.springframework.context.annotation.Import;

/**
 * @author David BRASSELY (david at gravitee.io)
 * @author GraviteeSource Team
 */
@Import({Oauth2Configuration.class})
public class OAuth2PolicyContext implements PolicyContext, PolicyContextProviderAware {

    @Property(name = "oauth.token.validation.endpoint.url", required = true, value = "http://localhost:8080/oauth/check_token")
    private String oauthTokenValidationEndPointURL;

    @Property(name = "oauth.token.validation.endpoint.http.method", required = true, value = "GET")
    private String oauthTokenValidationEndpointHttpMethod;

    @Property(name = "oauth.token.validation.endpoint.is.secure", required = true, value = "false")
    private String oauthTokenValidationEndPointIsSecure;

    @Property(name = "oauth.token.validation.endpoint.authorization.header.name", value = HttpHeaders.AUTHORIZATION)
    private String oauthTokenValidationEndPointAuthorizationHeaderName;

    @Property(name = "oauth.token.validation.endpoint.authorization.scheme", value = "Basic")
    private String oauthTokenValidationEndpointAuthorizationScheme;

    @Property(name = "oauth.token.validation.endpoint.authorization.value")
    private String oauthTokenValidationEndpointAuthorizationValue;

    @Property(name = "oauth.token.validation.endpoint.token.is.supplied.by.query.param", required = true, value = "true")
    private String oauthTokenValidationEndpointTokenIsSuppliedByQueryParam;

    @Property(name = "oauth.token.validation.endpoint.token.query.param.name", required = true, value = "token")
    private String oauthTokenValidationEndpointTokenQueryParamName;

    @Property(name = "oauth.token.validation.endpoint.token.is.supplied.by.http.header", required = true, value = "false")
    private String oauthTokenValidationEndpointTokenIsSuppliedByHttpHeader;

    @Property(name = "oauth.token.validation.endpoint.token.header.name")
    private String oauthTokenValidationEndpointTokenHeaderName;

    private PolicyContextProvider policyContextProvider;

    public String getOauthTokenValidationEndPointURL() {
        return oauthTokenValidationEndPointURL;
    }

    public void setOauthTokenValidationEndPointURL(String oauthTokenValidationEndPointURL) {
        this.oauthTokenValidationEndPointURL = oauthTokenValidationEndPointURL;
    }

    public String getOauthTokenValidationEndpointHttpMethod() {
        return oauthTokenValidationEndpointHttpMethod;
    }

    public void setOauthTokenValidationEndpointHttpMethod(String oauthTokenValidationEndpointHttpMethod) {
        this.oauthTokenValidationEndpointHttpMethod = oauthTokenValidationEndpointHttpMethod;
    }

    public Boolean oAuthTokenValidationEndPointIsSecure() {
        return Boolean.valueOf(oauthTokenValidationEndPointIsSecure);
    }

    public void setOauthTokenValidationEndPointIsSecure(String oauthTokenValidationEndPointIsSecure) {
        this.oauthTokenValidationEndPointIsSecure = oauthTokenValidationEndPointIsSecure;
    }

    public String getOauthTokenValidationEndPointAuthorizationHeaderName() {
        return oauthTokenValidationEndPointAuthorizationHeaderName;
    }

    public void setOauthTokenValidationEndPointAuthorizationHeaderName(String oauthTokenValidationEndPointAuthorizationHeaderName) {
        this.oauthTokenValidationEndPointAuthorizationHeaderName = oauthTokenValidationEndPointAuthorizationHeaderName;
    }

    public String getOauthTokenValidationEndpointAuthorizationScheme() {
        return oauthTokenValidationEndpointAuthorizationScheme;
    }

    public void setOauthTokenValidationEndpointAuthorizationScheme(String oauthTokenValidationEndpointAuthorizationScheme) {
        this.oauthTokenValidationEndpointAuthorizationScheme = oauthTokenValidationEndpointAuthorizationScheme;
    }

    public String getOauthTokenValidationEndpointAuthorizationValue() {
        return oauthTokenValidationEndpointAuthorizationValue;
    }

    public void setOauthTokenValidationEndpointAuthorizationValue(String oauthTokenValidationEndpointAuthorizationValue) {
        this.oauthTokenValidationEndpointAuthorizationValue = oauthTokenValidationEndpointAuthorizationValue;
    }

    public Boolean oAuthTokenValidationEndpointTokenIsSuppliedByQueryParam() {
        return Boolean.valueOf(oauthTokenValidationEndpointTokenIsSuppliedByQueryParam);
    }

    public void setOauthTokenValidationEndpointTokenIsSuppliedByQueryParam(String oauthTokenValidationEndpointTokenIsSuppliedByQueryParam) {
        this.oauthTokenValidationEndpointTokenIsSuppliedByQueryParam = oauthTokenValidationEndpointTokenIsSuppliedByQueryParam;
    }

    public String getOauthTokenValidationEndpointTokenQueryParamName() {
        return oauthTokenValidationEndpointTokenQueryParamName;
    }

    public void setOauthTokenValidationEndpointTokenQueryParamName(String oauthTokenValidationEndpointTokenQueryParamName) {
        this.oauthTokenValidationEndpointTokenQueryParamName = oauthTokenValidationEndpointTokenQueryParamName;
    }

    public Boolean oAuthTokenValidationEndpointTokenIsSuppliedByHttpHeader() {
        return Boolean.valueOf(oauthTokenValidationEndpointTokenIsSuppliedByHttpHeader);
    }

    public void setOauthTokenValidationEndpointTokenIsSuppliedByHttpHeader(String oauthTokenValidationEndpointTokenIsSuppliedByHttpHeader) {
        this.oauthTokenValidationEndpointTokenIsSuppliedByHttpHeader = oauthTokenValidationEndpointTokenIsSuppliedByHttpHeader;
    }

    public String getOauthTokenValidationEndpointTokenHeaderName() {
        return oauthTokenValidationEndpointTokenHeaderName;
    }

    public void setOauthTokenValidationEndpointTokenHeaderName(String oauthTokenValidationEndpointTokenHeaderName) {
        this.oauthTokenValidationEndpointTokenHeaderName = oauthTokenValidationEndpointTokenHeaderName;
    }

    public PolicyContextProvider getPolicyContextProvider() {
        return policyContextProvider;
    }

    @Override
    public void onActivation() throws Exception {
        HttpClient client = policyContextProvider.getComponent(HttpClient.class);
        client.init();
    }

    @Override
    public void onDeactivation() throws Exception {
        HttpClient client = policyContextProvider.getComponent(HttpClient.class);
        client.close();
    }

    @Override
    public void setPolicyContextProvider(PolicyContextProvider policyContextProvider) {
        this.policyContextProvider = policyContextProvider;
    }

    public <T> T getComponent(Class<T> clazz) {
        return policyContextProvider.getComponent(clazz);
    }
}
