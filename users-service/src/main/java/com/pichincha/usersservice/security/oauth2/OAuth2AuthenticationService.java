package com.pichincha.usersservice.security.oauth2;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pichincha.usersservice.domain.OAuthRegisteredClient;
import com.pichincha.usersservice.service.client.LoginFlowServiceClient;
import com.pichincha.usersservice.service.dto.OAuth2AccessToken;
import com.pichincha.usersservice.service.dto.OAuthCsrfToken;
import com.pichincha.usersservice.web.rest.errors.OauthErrorMapping;
import com.pichincha.usersservice.web.rest.errors.UnauthorizedException;
import com.pichincha.usersservice.web.rest.vm.LoginVM;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import com.pichincha.usersservice.repository.OAuthRegisteredClientRepository;

import java.util.*;


/**
 * Manages authentication cases for OAuth2 updating the cookies holding access and refresh tokens accordingly.
 * <p>
 * It can authenticate users, refresh the token cookies should they expire and log users out.
 */
@Service
public class OAuth2AuthenticationService {

    /**
     * Number of milliseconds to cache refresh token grants so we don't have to repeat them in case of parallel requests.
     */
    private static final long REFRESH_TOKEN_VALIDITY_MILLIS = 10000L;

    private final Logger log = LoggerFactory.getLogger(OAuth2AuthenticationService.class);

    /**
     * Used to contact the OAuth2 token endpoint.
     */
    private final OAuth2TokenEndpointClient authorizationClient;

    private final MessageSource messageSource;

    private final ObjectMapper objectMapper;

    private final OAuth2CookieHelper cookieHelper;
    private final OAuthRegisteredClientRepository registeredClientRepository;

    protected final LoginFlowServiceClient serviceClient;

    public OAuth2AuthenticationService(OAuth2TokenEndpointClient authorizationClient, ObjectMapper objectMapper, MessageSource messageSource,
                                       OAuth2CookieHelper cookieHelper, OAuthRegisteredClientRepository registeredClientRepository,
                                       LoginFlowServiceClient serviceClient) {
        this.authorizationClient = authorizationClient;
        this.objectMapper = objectMapper;
        this.messageSource = messageSource;
        this.cookieHelper = cookieHelper;
        this.registeredClientRepository = registeredClientRepository;
        this.serviceClient = serviceClient;
    }

    /**
     * Authenticate the user by username and password.
     *
     * @param request         the request coming from the client.
     * @param response        the response going back to the server.
     * @param loginVM         the params holding the username, password and rememberMe.
     * @param locale
     * @return the {@link OAuth2AccessToken} as a {@link ResponseEntity}. Will return {@code OK (200)}, if successful.
     * If the UAA cannot authenticate the user, the status code returned by UAA will be returned.
     */
    public ResponseEntity<OAuth2AccessToken> authenticate(HttpServletRequest request, HttpServletResponse response, LoginVM loginVM, GrantTypes grantTypes, Locale locale) {
        try {
            String username = loginVM.getUsername();
            String password = loginVM.getPassword();
            boolean rememberMe = loginVM.isRememberMe();
            OAuth2AccessToken accessToken = sendGrantToAuthenticate(grantTypes, username, password, locale, request);
            Map<String, String> headers = retrieveHeaders(request);
            HttpSession session = request.getSession(true);
            Map<String, Object> attributes = new HashMap<>();
            Optional<OAuthRegisteredClient> clientOptional = registeredClientRepository.findByClientId(headers.get("client_id"));
            OAuthRegisteredClient registeredClient = clientOptional.orElseThrow(() -> {
                ProblemDetail problemDetail = ProblemDetail.forStatus(401);
                return new UnauthorizedException(problemDetail);
            });
            attributes.put("registration_id", registeredClient.getId());
            attributes.put("code_verifier", headers.get("code_verifier"));
            OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                    .authorizationUri("/oauth2/authenticate")
                    .redirectUri(headers.get("redirect_uri"))
                    .clientId(registeredClient.getClientId())
                    .scope(registeredClient.getScopes())
                    .state(headers.get("state"))
                    .attributes(attributes)
                    .build();
            session.setAttribute(HttpSessionOAuth2AuthorizationRequestRepository.class.getName() + ".AUTHORIZATION_REQUEST", authorizationRequest);

            OAuth2Cookies cookies = new OAuth2Cookies();
            cookieHelper.createCookies(request, accessToken, rememberMe, cookies);
            cookies.addCookiesTo(response);
            if (log.isDebugEnabled()) {
                log.debug("successfully authenticated user {}", username);
            }
            return ResponseEntity.ok(accessToken);
        } catch (HttpClientErrorException ex) {
            log.error("failed to get OAuth2 tokens from UAA", ex);
            try {
                log.info("El cuerpo es {}", ex.getResponseBodyAsString());
                OauthErrorMapping errorMapping = objectMapper.readValue(ex.getResponseBodyAsString(), OauthErrorMapping.class);
                throw new BadCredentialsException(errorMapping.getErrorDescription());
            } catch (JsonProcessingException e) {
                log.error("failed to get OAuth2 tokens from UAA");
                throw new BadCredentialsException(ex.getMessage());
            }
        }
    }

    private OAuth2AccessToken sendGrantToAuthenticate(GrantTypes grantTypes, String username, String password, Locale locale, HttpServletRequest request) {
        return authorizationClient.sendPasswordGrant(username, password, grantTypes, retrieveHeaders(request), locale);
    }

    public OAuth2AuthorizationCode sendLogin(LoginVM loginVM, HttpServletRequest request) {
        Map<String, String> headers = retrieveHeaders(request);
        ResponseEntity<OAuthCsrfToken> tokenResponseEntity = serviceClient.retrieveCsrfToken(headers);
        HttpStatus httpStatus = HttpStatus.valueOf(tokenResponseEntity.getStatusCode().value());
        if (HttpStatus.OK != httpStatus) {
            log.debug("failed to authenticate user with OAuth2 token endpoint, status: {}", httpStatus.value());
            throw new HttpClientErrorException(httpStatus);
        }
        OAuthCsrfToken authCsrfToken = tokenResponseEntity.getBody();
        Map<String, String> params = new HashMap<>();
        String username = loginVM.getUsername();
        log.info("Token antes de enviar: {}", username);
        log.debug("contacting OAuth2 token endpoint to login user: {}", username);
        String password = loginVM.getPassword();
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
        HttpSession session = request.getSession(true);
        Map<String, Object> attributes = new HashMap<>();
        Optional<OAuthRegisteredClient> clientOptional = registeredClientRepository.findByClientId(headers.get("client_id"));
        OAuthRegisteredClient registeredClient = clientOptional.orElseThrow(() -> {
            ProblemDetail problemDetail = ProblemDetail.forStatus(401);
            return new UnauthorizedException(problemDetail);
        });
        attributes.put("registration_id", registeredClient.getId());
        attributes.put("code_verifier", headers.get("code_verifier"));
        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("/oauth2/authenticate")
                .redirectUri(headers.get("redirect_uri"))
                .clientId(registeredClient.getClientId())
                .scope(registeredClient.getScopes())
                .state(headers.get("state"))
                .attributes(attributes)
                .build();
        session.setAttribute(HttpSessionOAuth2AuthorizationRequestRepository.class.getName() + ".AUTHORIZATION_REQUEST", authorizationRequest);
        return responseEntity.getBody();
    }

    private Map<String, String> retrieveHeaders(HttpServletRequest request) {
        Map<String, String> headers = new HashMap<>();
        String clientId = request.getHeader("application_client");
        headers.put("client_id", clientId);
        String redirectUri = request.getHeader("redirect_uri");
        headers.put("redirect_uri", redirectUri);
        String scope = request.getHeader("scope");
        headers.put("scope", scope);
        String responseType = request.getHeader("response_type");
        headers.put("response_type", responseType);
        String responseMode = request.getHeader("response_mode");
        headers.put("response_mode", responseMode);
        String codeChallengeMethod = request.getHeader("code_challenge_method");
        headers.put("code_challenge_method", codeChallengeMethod);
        String codeChallenge = request.getHeader("code_challenge");
        headers.put("code_challenge", codeChallenge);
        String codeVerifier = request.getHeader("code_verifier");
        headers.put("code_verifier", codeVerifier);
        String state = request.getHeader("state");
        headers.put("state", state);
        String nonce = request.getHeader("nonce");
        headers.put("nonce", nonce);
        return headers;
    }
}
