package com.pichincha.authorizationserver.security;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;

@Service
public class RegisterClientService {
    private final PasswordEncoder passwordEncoder;

    private final RegisteredClientRepository clientRepository;

    public RegisterClientService(PasswordEncoder passwordEncoder, RegisteredClientRepository clientRepository) {
        this.passwordEncoder = passwordEncoder;
        this.clientRepository = clientRepository;
    }

    @Transactional
    public void initialRegistration() {
        TokenSettings tokenSettings = TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofMinutes(30))
                .refreshTokenTimeToLive(Duration.ofMinutes(30))
                .authorizationCodeTimeToLive(Duration.ofMinutes(30))
                .build();

        List<String> customScopes = List.of(OidcScopes.OPENID, OidcScopes.PROFILE, "message.read", "message.write");

        RegisteredClient customRegisterClient = RegisteredClient.withId("oauth-web-client")
                .clientName("application-client")
                .clientId("application-client")
                .clientSecret(passwordEncoder.encode("secret"))
                .clientIdIssuedAt(Instant.now().plus(30, ChronoUnit.DAYS))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scopes(items -> items.addAll(customScopes))
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
                .redirectUri("http://127.0.0.1:8081/oauth2/authorize")
                .redirectUri("http://127.0.0.1:8080/authorized")
                .redirectUri("https://oidcdebugger.com/debug")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                .tokenSettings(tokenSettings)
                .build();


        List<RegisteredClient> registeredClients = List.of(customRegisterClient);
        for (RegisteredClient registeredClient : registeredClients) {
            Optional<RegisteredClient> optional = Optional.ofNullable(clientRepository.findByClientId(registeredClient.getClientId()));
            optional.ifPresentOrElse(clientRepository::save, () -> clientRepository.save(registeredClient));
        }
    }
}
