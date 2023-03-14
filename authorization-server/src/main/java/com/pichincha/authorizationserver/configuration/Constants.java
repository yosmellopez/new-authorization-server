package com.pichincha.authorizationserver.configuration;

import org.springframework.security.oauth2.core.AuthorizationGrantType;

/**
 * Application constants.
 */
public final class Constants {

    // Regex for acceptable logins
    public static final String LOGIN_REGEX = "^(?>[a-zA-Z0-9!$&*+=?^_`{|}~.-]+@[a-zA-Z0-9-]+(?:\\.[a-zA-Z0-9-]+)*)|(?>[_.@A-Za-z0-9-]+)$";

    public static final String SYSTEM_ACCOUNT = "system";
    public static final String DEFAULT_LANGUAGE = "en";
    public static final String ANONYMOUS_USER = "anonymoususer";
    public static final AuthorizationGrantType IMPLICIT = new AuthorizationGrantType("implicit");
    public static final AuthorizationGrantType MFA = new AuthorizationGrantType("mfa");
    public static final AuthorizationGrantType QR_CODE_AUTH = new AuthorizationGrantType("qr_code_auth");
    public static final AuthorizationGrantType LOCAL_AUTH = new AuthorizationGrantType("local_auth");
    public static final AuthorizationGrantType UNLOCK_SESSION = new AuthorizationGrantType("unlock_session");
    public static final AuthorizationGrantType AUTHORIZATION_CODE = new AuthorizationGrantType("authorization_code");

    private Constants() {
    }
}
