package org.ylplabs.usersservice.service.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.ylplabs.usersservice.service.dto.OAuth2AccessToken;
import org.ylplabs.usersservice.service.dto.OAuthCsrfToken;

import java.util.Map;

import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;

@FeignClient(value = "login-client",
        url = "http://localhost:8081",
        path = "/v1/oauth2",
        configuration = OAuth2FeignConfiguration.class)
public interface LoginFlowServiceClient {
    @PostMapping("/authorize")
    ResponseEntity<OAuthCsrfToken> retrieveCsrfToken(@RequestParam Map<String, String> params);

    @PostMapping(value = "/authenticate", consumes = APPLICATION_FORM_URLENCODED_VALUE)
    ResponseEntity<Void> authenticate(@RequestBody Map<String, ?> form);

    @PostMapping(value = "/authorize", consumes = APPLICATION_FORM_URLENCODED_VALUE)
    ResponseEntity<OAuth2AuthorizationCode> checkAuthorization(@RequestParam Map<String, String> params, @RequestHeader("Cookie") String cookie);

    @PostMapping(value = "/token", consumes = APPLICATION_FORM_URLENCODED_VALUE)
    ResponseEntity<OAuth2AccessToken> getToken(@RequestBody Map<String, ?> form);

    @PostMapping(value = "/token", consumes = APPLICATION_FORM_URLENCODED_VALUE)
    ResponseEntity<OAuth2AccessToken> getMfaToken(@RequestBody Map<String, ?> form, @RequestHeader(HttpHeaders.AUTHORIZATION) String authorization);
}
