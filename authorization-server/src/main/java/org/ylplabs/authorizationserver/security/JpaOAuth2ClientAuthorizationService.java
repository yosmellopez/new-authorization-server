package org.ylplabs.authorizationserver.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.ylplabs.authorizationserver.domain.OAuthClientAuthorization;
import org.ylplabs.authorizationserver.domain.OAuthRegisteredClient;
import org.ylplabs.authorizationserver.repository.OAuthClientAuthorizationRepository;
import org.ylplabs.authorizationserver.repository.OAuthRegisteredClientRepository;

import java.util.Optional;

@Component
public class JpaOAuth2ClientAuthorizationService implements OAuth2AuthorizedClientService {
    private final OAuthClientAuthorizationRepository authorizationRepository;
    private final OAuthRegisteredClientRepository clientRepository;

    public JpaOAuth2ClientAuthorizationService(OAuthClientAuthorizationRepository authorizationRepository, OAuthRegisteredClientRepository clientRepository) {
        this.clientRepository = clientRepository;
        Assert.notNull(authorizationRepository, "authorizationRepository cannot be null");
        this.authorizationRepository = authorizationRepository;
    }

    @Override
    public OAuth2AuthorizedClient loadAuthorizedClient(String clientRegistrationId, String principalName) {
        Optional<OAuthClientAuthorization> optional = authorizationRepository.findByRegisteredClientIdAndPrincipalName(clientRegistrationId, principalName);
        return optional
                .map(oAuthClientAuthorization -> this.mapToClient(oAuthClientAuthorization, principalName))
                .orElse(null);
    }

    private OAuth2AuthorizedClient mapToClient(OAuthClientAuthorization client, String principalName) {
        Optional<OAuthRegisteredClient> optional = clientRepository.findByClientIdOrId(client.getRegisteredClientId(), client.getRegisteredClientId());
        OAuthRegisteredClient registeredClient = optional.orElseThrow();
        OAuth2AccessToken.TokenType tokenType = OAuth2AccessToken.TokenType.BEARER;

        ClientRegistration registration = ClientRegistration.withRegistrationId(client.getId())
                .clientId(registeredClient.getClientId())
                .clientSecret("secret")
                .clientName(registeredClient.getClientName())
                .redirectUri(registeredClient.getRedirectUris())
                .authorizationGrantType(new AuthorizationGrantType(registeredClient.getAuthorizationGrantTypes()))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .scope(registeredClient.getScopes())
                .authorizationUri("http://localhost:8081/v1/oauth2/authorize")
                .issuerUri("http://localhost:8081")
                .tokenUri("http://localhost:8081/v1/oauth2/token")
                .userInfoUri("http://localhost:8081/v1/oauth2/userinfo")
                .jwkSetUri("http://localhost:8081/v1/oauth2/jwks")
                .build();
        OAuth2AccessToken oAuth2AccessToken = new OAuth2AccessToken(tokenType, client.getAccessTokenValue(), client.getAccessTokenIssuedAt(), client.getAccessTokenExpiresAt());
        OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(client.getRefreshTokenValue(), client.getRefreshTokenIssuedAt(), client.getRefreshTokenExpiresAt());
        return new OAuth2AuthorizedClient(registration, principalName, oAuth2AccessToken, refreshToken);
    }

    @Override
    public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal) {

    }

    @Override
    public void removeAuthorizedClient(String clientRegistrationId, String principalName) {

    }
}
