package org.ylplabs.authorizationserver.domain;

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
 * not an ignored comment
 */
@Data
@Entity
@Table(name = "oauth_registered_client")
public class OAuthRegisteredClient implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    @Id
    @Column(name = "id")
    private String id;

    @Column(name = "client_id")
    private String clientId;

    @Column(name = "client_id_issued_at")
    private Instant clientIdIssuedAt;

    @Column(name = "client_secret")
    private String clientSecret;

    @Column(name = "client_secret_expires_at")
    private Instant clientSecretExpiresAt;

    @Column(name = "client_name")
    private String clientName;

    @Size(max = 1000)
    @Column(name = "client_authentication_methods", length = 1000)
    private String clientAuthenticationMethods;

    @Size(max = 1000)
    @Column(name = "authorization_grant_types", length = 1000)
    private String authorizationGrantTypes;

    @Size(max = 1000)
    @Column(name = "redirect_uris", length = 1000)
    private String redirectUris;

    @Size(max = 1000)
    @Column(name = "scopes", length = 1000)
    private String scopes;

    @Size(max = 2000)
    @Column(name = "client_settings", length = 2000)
    private String clientSettings;

    @Size(max = 2000)
    @Column(name = "token_settings", length = 2000)
    private String tokenSettings;

}
