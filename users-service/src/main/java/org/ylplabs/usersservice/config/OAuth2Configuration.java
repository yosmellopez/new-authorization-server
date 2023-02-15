package org.ylplabs.usersservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;

import java.time.Duration;


@Configuration
public class OAuth2Configuration {

    @Bean
    public OAuth2AuthorizedClientManager authorizedClientManager(ClientRegistrationRepository registrationRepository, OAuth2AuthorizedClientRepository clientRepository) {
        DefaultOAuth2AuthorizedClientManager authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(registrationRepository, clientRepository);

        authorizedClientManager.setAuthorizedClientProvider(
            OAuth2AuthorizedClientProviderBuilder
                .builder()
                .authorizationCode()
                .refreshToken(builder -> builder.clockSkew(Duration.ofMinutes(1)))
                .clientCredentials()
                .build()
        );
        return authorizedClientManager;
    }

}
