package com.pichincha.usersservice.web.rest;

import com.pichincha.usersservice.security.oauth2.GrantTypes;
import com.pichincha.usersservice.security.oauth2.OAuth2AuthenticationService;
import com.pichincha.usersservice.service.client.ConversionServiceClient;
import com.pichincha.usersservice.service.dto.ConversionResponse;
import com.pichincha.usersservice.service.dto.CurrencyConversion;
import com.pichincha.usersservice.service.dto.OAuth2AccessToken;
import com.pichincha.usersservice.web.rest.vm.LoginVM;
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

import java.util.Locale;

/**
 * Controller to authenticate users.
 */
@RestController
@RequestMapping("/api")
public class UserJWTController {

    private final Logger log = LoggerFactory.getLogger(UserJWTController.class);

    private final OAuth2AuthenticationService authenticationService;
    private final ConversionServiceClient conversionServiceClient;

    public UserJWTController(OAuth2AuthenticationService authenticationService, ConversionServiceClient conversionServiceClient) {
        this.authenticationService = authenticationService;
        this.conversionServiceClient = conversionServiceClient;
    }

    @PostMapping("/authenticate")
    public ResponseEntity<OAuth2AccessToken> authorize(@Valid @RequestBody LoginVM loginVM, HttpServletRequest request, HttpServletResponse response, Locale locale) {
        return authenticationService.authenticate(request, response, loginVM, GrantTypes.PASSWORD, locale);
    }

    @PostMapping("/convert-currencies")
    public ResponseEntity<ConversionResponse> convertCurrencies(@Valid @RequestBody CurrencyConversion currencyConversion) {
        return conversionServiceClient.convertCurrencies(currencyConversion);
    }
}
