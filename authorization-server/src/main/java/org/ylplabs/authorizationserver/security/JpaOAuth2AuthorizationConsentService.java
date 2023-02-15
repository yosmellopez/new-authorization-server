package org.ylplabs.authorizationserver.security;

import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.ylplabs.authorizationserver.domain.OAuthAuthorizationConsent;
import org.ylplabs.authorizationserver.repository.OAuthAuthorizationConsentRepository;

import java.util.HashSet;
import java.util.Set;

@Component
public class JpaOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {
    private final OAuthAuthorizationConsentRepository authAuthorizationConsentRepository;
    private final RegisteredClientRepository registeredClientRepository;

    public JpaOAuth2AuthorizationConsentService(OAuthAuthorizationConsentRepository authAuthorizationConsentRepository, RegisteredClientRepository registeredClientRepository) {
        Assert.notNull(authAuthorizationConsentRepository, "authorizationConsentRepository cannot be null");
        Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
        this.authAuthorizationConsentRepository = authAuthorizationConsentRepository;
        this.registeredClientRepository = registeredClientRepository;
    }

    @Override
    public void save(OAuth2AuthorizationConsent authorizationConsent) {
        Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
        this.authAuthorizationConsentRepository.save(toEntity(authorizationConsent));
    }

    @Override
    public void remove(OAuth2AuthorizationConsent authorizationConsent) {
        Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
        this.authAuthorizationConsentRepository.deleteByRegisteredClientIdAndPrincipalName(
                authorizationConsent.getRegisteredClientId(), authorizationConsent.getPrincipalName());
    }

    @Override
    public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
        Assert.hasText(registeredClientId, "registeredClientId cannot be empty");
        Assert.hasText(principalName, "principalName cannot be empty");
        return this.authAuthorizationConsentRepository.findByRegisteredClientIdAndPrincipalName(
                registeredClientId, principalName).map(this::toObject).orElse(null);
    }

    private OAuth2AuthorizationConsent toObject(OAuthAuthorizationConsent oauthAuthorizationConsent) {
        String registeredClientId = oauthAuthorizationConsent.getRegisteredClientId();
        RegisteredClient registeredClient = this.registeredClientRepository.findById(registeredClientId);
        if (registeredClient == null) {
            throw new DataRetrievalFailureException(
                    "The RegisteredClient with id '" + registeredClientId + "' was not found in the JpaRegisteredClientRepository.");
        }

        OAuth2AuthorizationConsent.Builder builder = OAuth2AuthorizationConsent.withId(
                registeredClientId, oauthAuthorizationConsent.getPrincipalName());
        if (oauthAuthorizationConsent.getAuthorities() != null) {
            for (String authority : StringUtils.commaDelimitedListToSet(oauthAuthorizationConsent.getAuthorities())) {
                builder.authority(new SimpleGrantedAuthority(authority));
            }
        }

        return builder.build();
    }

    private OAuthAuthorizationConsent toEntity(OAuth2AuthorizationConsent authorizationConsent) {
        OAuthAuthorizationConsent entity = new OAuthAuthorizationConsent();
        entity.setRegisteredClientId(authorizationConsent.getRegisteredClientId());
        entity.setPrincipalName(authorizationConsent.getPrincipalName());

        Set<String> authorities = new HashSet<>();
        for (GrantedAuthority authority : authorizationConsent.getAuthorities()) {
            authorities.add(authority.getAuthority());
        }
        entity.setAuthorities(StringUtils.collectionToCommaDelimitedString(authorities));

        return entity;
    }
}
