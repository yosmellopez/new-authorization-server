package com.pichincha.usersservice.repository;

import com.pichincha.usersservice.domain.OAuthClientAuthorization;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;

@Repository
public interface OAuthClientAuthorizationRepository extends JpaRepository<OAuthClientAuthorization, String> {


    Optional<OAuthClientAuthorization> findByState(String state);

    Optional<OAuthClientAuthorization> findByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);

    Optional<OAuthClientAuthorization> findByAuthorizationCodeValue(String authorizationCode);

    Optional<OAuthClientAuthorization> findByPrincipalNameAndAccessTokenExpiresAt(String principalName, Instant expiresAt);

    Optional<OAuthClientAuthorization> findByAccessTokenValue(String accessToken);

    Optional<OAuthClientAuthorization> findByRefreshTokenValue(String refreshToken);

    @Query("select a from OAuthClientAuthorization a where a.state = :token" +
            " or a.authorizationCodeValue = :token" +
            " or a.accessTokenValue = :token" +
            " or a.refreshTokenValue = :token"
    )
    Optional<OAuthClientAuthorization> findByStateOrAuthorizationCodeValueOrAccessTokenValueOrRefreshTokenValue(@Param("token") String token);
}
