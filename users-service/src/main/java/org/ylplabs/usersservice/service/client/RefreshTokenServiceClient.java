package org.ylplabs.usersservice.service.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.ylplabs.usersservice.service.dto.OAuth2AccessToken;

import java.util.Map;

import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;

@FeignClient(value = "refresh-client",
        url = "http://localhost:9999",
        path = "/v1/oauth2",
        configuration = OAuth2FeignConfiguration.class)
public interface RefreshTokenServiceClient {
    @PostMapping(value = "/token", consumes = APPLICATION_FORM_URLENCODED_VALUE)
    ResponseEntity<OAuth2AccessToken> sendRefreshToken(@RequestBody Map<String, ?> form);
}
