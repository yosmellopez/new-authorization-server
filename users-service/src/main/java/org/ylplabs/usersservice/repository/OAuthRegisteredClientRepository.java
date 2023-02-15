package org.ylplabs.usersservice.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.ylplabs.usersservice.domain.OAuthRegisteredClient;

import java.util.Optional;

/**
 * Spring Data JPA repository for the OauthRegisteredClient entity.
 */
@Repository
public interface OAuthRegisteredClientRepository extends JpaRepository<OAuthRegisteredClient, String> {
    Optional<OAuthRegisteredClient> findByClientIdOrId(String clientId, String id);

    Optional<OAuthRegisteredClient> findByClientId(String clientId);

}
