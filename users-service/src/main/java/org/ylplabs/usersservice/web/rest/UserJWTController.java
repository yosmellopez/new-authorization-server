package org.ylplabs.usersservice.web.rest;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.ylplabs.usersservice.security.oauth2.GrantTypes;
import org.ylplabs.usersservice.security.oauth2.OAuth2AuthenticationService;
import org.ylplabs.usersservice.service.dto.OAuth2AccessToken;
import org.ylplabs.usersservice.web.rest.vm.LoginVM;

import java.util.Locale;

/**
 * Controller to authenticate users.
 */
@RestController
@RequestMapping("/api")
public class UserJWTController {

    private final Logger log = LoggerFactory.getLogger(UserJWTController.class);

    private final OAuth2AuthenticationService authenticationService;

    public UserJWTController(OAuth2AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("/authenticate")
    public ResponseEntity<OAuth2AccessToken> authorize(@Valid @RequestBody LoginVM loginVM, HttpServletRequest request, HttpServletResponse response, Locale locale) {
        return authenticationService.authenticate(request, response, loginVM, GrantTypes.PASSWORD, locale);
    }
}
