package com.pichincha.authorizationserver.repository;

import com.pichincha.authorizationserver.domain.OAuthAuthorizationConsent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OAuthAuthorizationConsentRepository extends JpaRepository<OAuthAuthorizationConsent, OAuthAuthorizationConsent.AuthorizationConsentId> {
    Optional<OAuthAuthorizationConsent> findByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);

    void deleteByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);

}
