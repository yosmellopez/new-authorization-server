package org.ylplabs.usersservice.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;

/**
 * A OAuthClientAuthorization.
 */
@Data
@Entity
@Table(name = "oauth_client_authorization")
public class OAuthClientAuthorization implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    @Id
    @Column(name = "id")
    private String id;

    @Column(name = "registered_client_id")
    private String registeredClientId;

    @Column(name = "principal_name")
    private String principalName;

    @Column(name = "authorization_grant_type")
    private String authorizationGrantType;

    @Size(max = 4000)
    @Column(name = "attributes")
    private String attributes;

    @Size(max = 500)
    @Column(name = "state")
    private String state;

    @Size(max = 1000)
    @Column(name = "authorized_scopes")
    private String authorizedScopes;

    @Size(max = 4000)
    @Column(name = "authorization_code_value")
    private String authorizationCodeValue;

    @Column(name = "authorization_code_issued_at")
    private Instant authorizationCodeIssuedAt;

    @Column(name = "authorization_code_expires_at")
    private Instant authorizationCodeExpiresAt;

    @Size(max = 2000)
    @Column(name = "authorization_code_metadata")
    private String authorizationCodeMetadata;

    @Size(max = 4000)
    @Column(name = "access_token_value")
    private String accessTokenValue;

    @Column(name = "access_token_issued_at")
    private Instant accessTokenIssuedAt;

    @Column(name = "access_token_expires_at")
    private Instant accessTokenExpiresAt;

    @Size(max = 2000)
    @Column(name = "access_token_metadata")
    private String accessTokenMetadata;

    @Column(name = "access_token_type")
    private String accessTokenType;

    @Size(max = 1000)
    @Column(name = "access_token_scopes")
    private String accessTokenScopes;

    @Size(max = 4000)
    @Column(name = "refresh_token_value")
    private String refreshTokenValue;

    @Column(name = "refresh_token_issued_at")
    private Instant refreshTokenIssuedAt;

    @Column(name = "refresh_token_expires_at")
    private Instant refreshTokenExpiresAt;

    @Size(max = 2000)
    @Column(name = "refresh_token_metadata")
    private String refreshTokenMetadata;

    @Size(max = 4000)
    @Column(name = "oidc_id_token_value")
    private String oidcIdTokenValue;

    @Column(name = "oidc_id_token_issued_at")
    private Instant oidcIdTokenIssuedAt;

    @Column(name = "oidc_id_token_expires_at")
    private Instant oidcIdTokenExpiresAt;

    @Size(max = 2000)
    @Column(name = "oidc_id_token_metadata")
    private String oidcIdTokenMetadata;

    @Size(max = 2000)
    @Column(name = "oidc_id_token_claims")
    private String oidcIdTokenClaims;
}
