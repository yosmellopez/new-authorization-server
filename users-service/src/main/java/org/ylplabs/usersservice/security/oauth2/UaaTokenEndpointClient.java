package org.ylplabs.usersservice.security.oauth2;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.util.Base64Utils;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.ylplabs.usersservice.service.client.LoginFlowServiceClient;

import java.nio.charset.StandardCharsets;

/**
 * OAuth2RegisteredClient talking to UAA's token endpoint to do different OAuth2 grants.
 */
@Component
public class UaaTokenEndpointClient extends OAuth2TokenEndpointClientAdapter implements OAuth2TokenEndpointClient {

    public UaaTokenEndpointClient(@Qualifier("restTemplate") RestTemplate restTemplate, LoginFlowServiceClient serviceClient) {
        super(restTemplate, serviceClient);
    }

    @Override
    protected void addAuthentication(HttpHeaders reqHeaders, MultiValueMap<String, String> formParams) {
        reqHeaders.add("Authorization", getAuthorizationHeader());
    }

    /**
     * @return a Basic authorization header to be used to talk to UAA.
     */
    protected String getAuthorizationHeader() {
        String authorization = "admin" + ":" + "admin";
        return "Basic " + Base64Utils.encodeToString(authorization.getBytes(StandardCharsets.UTF_8));
    }
}
