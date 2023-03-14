package com.pichincha.usersservice.security.oauth2;

import com.pichincha.usersservice.service.client.LoginFlowServiceClient;
import com.pichincha.usersservice.service.dto.OAuth2AccessToken;
import com.pichincha.usersservice.service.dto.OAuthCsrfToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.*;

/**
 * Default base class for an {@link OAuth2TokenEndpointClient}.
 * Individual implementations for a particular OAuth2 provider can use this as a starting point.
 */
public abstract class OAuth2TokenEndpointClientAdapter implements OAuth2TokenEndpointClient {

    protected final RestTemplate restTemplate;
    protected final LoginFlowServiceClient serviceClient;

    private final Logger log = LoggerFactory.getLogger(OAuth2TokenEndpointClientAdapter.class);

    public OAuth2TokenEndpointClientAdapter(RestTemplate restTemplate, LoginFlowServiceClient serviceClient) {
        this.restTemplate = restTemplate;
        this.serviceClient = serviceClient;
    }

    /**
     * Sends a password grant to the token endpoint.
     *
     * @param username the username to authenticate.
     * @param password his password.
     * @param locale
     * @return the access token.
     */
    @Override
    public OAuth2AccessToken sendPasswordGrant(String username, String password, GrantTypes grantTypes, Map<String, String> headers, Locale locale) {
        log.debug("contacting OAuth2 token endpoint to login user: {}", username);
        ResponseEntity<OAuthCsrfToken> tokenResponseEntity = serviceClient.retrieveCsrfToken(headers);
        HttpStatus httpStatus = HttpStatus.valueOf(tokenResponseEntity.getStatusCode().value());
        if (HttpStatus.OK != httpStatus) {
            log.debug("failed to authenticate user with OAuth2 token endpoint, status: {}", httpStatus.value());
            throw new HttpClientErrorException(httpStatus);
        }
        OAuthCsrfToken authCsrfToken = tokenResponseEntity.getBody();
        Map<String, String> params = new HashMap<>();
        params.put("username", username.toLowerCase());
        params.put("password", password);
        params.put(authCsrfToken.getParameterName(), authCsrfToken.getToken());
        ResponseEntity<Void> response = serviceClient.authenticate(params);
        httpStatus = HttpStatus.valueOf(response.getStatusCode().value());
        if (HttpStatus.OK != httpStatus) {
            log.debug("failed to authenticate user with OAuth2 token endpoint, status: {}", response.getStatusCode());
            throw new HttpClientErrorException(response.getStatusCode());
        }
        HttpHeaders httpHeaders = response.getHeaders();
        List<String> cookies = httpHeaders.get("set-cookie");
        headers.put("scope", "openid profile message.read message.write");
        ResponseEntity<OAuth2AuthorizationCode> responseEntity = serviceClient.checkAuthorization(headers, String.join(";", cookies));
        httpStatus = HttpStatus.valueOf(responseEntity.getStatusCode().value());
        if (HttpStatus.OK != httpStatus) {
            log.debug("failed to authenticate user with OAuth2 token endpoint, status: {}", response.getStatusCode());
            throw new HttpClientErrorException(response.getStatusCode());
        }
        OAuth2AuthorizationCode code = responseEntity.getBody();
        headers.put("grant_type", "authorization_code");
        headers.put("code", code.getTokenValue());
        headers.put("client_secret", "secret");
        headers.remove("scope");
        headers.remove("response_mode");
        headers.remove("response_type");
        ResponseEntity<OAuth2AccessToken> entityToken = serviceClient.getToken(headers);

        httpStatus = HttpStatus.valueOf(entityToken.getStatusCode().value());
        if (HttpStatus.OK != httpStatus) {
            log.debug("failed to authenticate user with OAuth2 token endpoint, status: {}", response.getStatusCode());
            throw new HttpClientErrorException(response.getStatusCode());
        }
        OAuth2AccessToken accessToken = entityToken.getBody();
        OAuth2AccessTokenResponse.withToken(accessToken.getAccessToken())
                .refreshToken(accessToken.getRefreshToken())
                .expiresIn(accessToken.getExpiresIn())
                .scopes(Set.of("openid", "profile", "message.read", "message.write"))
                .tokenType(TokenType.BEARER)
                .build();
        return accessToken;
    }

    /**
     * Sends a refresh grant to the token endpoint using the current refresh token to obtain new tokens.
     *
     * @param refreshTokenValue the refresh token to use to obtain new tokens.
     * @param locale
     * @return the new, refreshed access token.
     */
    @Override
    public OAuth2AccessToken sendRefreshGrant(String refreshTokenValue, Locale locale) {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "refresh_token");
        params.add("refresh_token", refreshTokenValue);
        HttpHeaders headers = new HttpHeaders();
        addAuthentication(headers, params);
        headers.add(HttpHeaders.COOKIE, "NG_TRANSLATE_LANG_KEY=" + locale.getLanguage());
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(params, headers);
        log.debug("contacting OAuth2 token endpoint to refresh OAuth2 JWT tokens");
        ResponseEntity<OAuth2AccessToken> responseEntity = restTemplate.postForEntity(getTokenEndpoint(), entity, OAuth2AccessToken.class);
        log.info("refreshed OAuth2 JWT cookies using refresh_token grant");
        return responseEntity.getBody();
    }

    @Override
    public OAuth2AccessToken sendMFAGrant(String username, String password, Locale locale) {
        Map<String, String> params = new HashMap<>();
        params.put("grant_type", GrantTypes.MFA.name().toLowerCase(locale));
        params.put("token", password);
        params.put("access_token", username);
        params.put("client_id", "application-client");
//        HashMap<String, String> headers = new HashMap<>();
//        headers.put(HttpHeaders.AUTHORIZATION, "Bearer " + username);
//        headers.put(HttpHeaders.COOKIE, "NG_TRANSLATE_LANG_KEY=" + locale.getLanguage());
        ResponseEntity<OAuth2AccessToken> responseEntity = serviceClient.getMfaToken(params, "Bearer " + username);
        HttpStatus httpStatus = HttpStatus.valueOf(responseEntity.getStatusCode().value());
        if (HttpStatus.OK != httpStatus) {
            log.debug("failed to authenticate user with OAuth2 token endpoint, status: {}", responseEntity.getStatusCode());
            throw new HttpClientErrorException(responseEntity.getStatusCode());
        }
        log.info("refreshed OAuth2 JWT cookies using refresh_token grant");
        return responseEntity.getBody();
    }

    /**
     * Send a refresh_token grant to the token endpoint.
     *
     * @param accessTokenValue  the access token used to authenticate.
     * @param refreshTokenValue the refresh token used to get new tokens.
     * @param username          the username to unlock the session.
     * @param password          the password to unlock the session.
     * @param locale            the locale to get messages in locale
     * @return the new access/refresh token pair.
     */
    @Override
    public OAuth2AccessToken sendUnlockGrant(String accessTokenValue, String refreshTokenValue, String username, String password, Locale locale) {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "unlock_session");
        params.set("username", username.toLowerCase());
        params.set("password", password);
        params.set("access_token", accessTokenValue);
        params.add("refresh_token", refreshTokenValue);
        HttpHeaders headers = new HttpHeaders();
        addAuthentication(headers, params);
        headers.add(HttpHeaders.COOKIE, "NG_TRANSLATE_LANG_KEY=" + locale.getLanguage());
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(params, headers);
        log.debug("contacting OAuth2 token endpoint to refresh OAuth2 JWT tokens");
        ResponseEntity<OAuth2AccessToken> responseEntity = restTemplate.postForEntity(getTokenEndpoint(), entity, OAuth2AccessToken.class);
        log.info("refreshed OAuth2 JWT cookies using refresh_token grant");
        return responseEntity.getBody();
    }


    protected abstract void addAuthentication(HttpHeaders reqHeaders, MultiValueMap<String, String> formParams);

    /**
     * Returns the configured OAuth2 token endpoint URI.
     *
     * @return the OAuth2 token endpoint URI.
     */
    protected String getTokenEndpoint() {
        return "http://localhost:8081/v1/oauth2/token";
    }

}
