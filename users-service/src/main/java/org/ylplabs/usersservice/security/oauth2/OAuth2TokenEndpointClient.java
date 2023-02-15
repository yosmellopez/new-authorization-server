package org.ylplabs.usersservice.security.oauth2;


import org.ylplabs.usersservice.service.dto.OAuth2AccessToken;

import java.util.Locale;
import java.util.Map;

/**
 * OAuth2RegisteredClient talking to an OAuth2 Authorization server token endpoint.
 *
 * @see UaaTokenEndpointClient
 * @see OAuth2TokenEndpointClientAdapter
 */
public interface OAuth2TokenEndpointClient {

    /**
     * Send a password grant to the token endpoint.
     *
     * @param username the username to authenticate.
     * @param password his password.
     * @param locale
     * @return the access token and enclosed refresh token received from the token endpoint.
     */

    OAuth2AccessToken sendPasswordGrant(String username, String password, GrantTypes grantTypes, Map<String, String> headers, Locale locale);

    /**
     * Send a refresh_token grant to the token endpoint.
     *
     * @param refreshTokenValue the refresh token used to get new tokens.
     * @param locale
     * @return the new access/refresh token pair.
     */
    OAuth2AccessToken sendRefreshGrant(String refreshTokenValue, Locale locale);

    /**
     * Send a refresh_token grant to the token endpoint.
     *
     * @param accessTokenValue  the access token used to authenticate.
     * @param refreshTokenValue the refresh token used to get new tokens.
     * @param username          the username to unlock the session.
     * @param password          the password to unlock the session.
     * @param locale
     * @return the new access/refresh token pair.
     */
    OAuth2AccessToken sendUnlockGrant(String accessTokenValue, String refreshTokenValue, String username, String password, Locale locale);

    OAuth2AccessToken sendMFAGrant(String username, String password, Locale locale);
}
