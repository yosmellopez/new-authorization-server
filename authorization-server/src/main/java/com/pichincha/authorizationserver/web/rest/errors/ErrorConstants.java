package com.pichincha.authorizationserver.web.rest.errors;

import java.net.URI;

public final class ErrorConstants {

    public static final String ERR_CONCURRENCY_FAILURE = "error.concurrencyFailure";

    public static final String ERR_VALIDATION = "error.validation";

    public static final String ACCESS_TOKEN_EXPIRED = "error.tokenExpired";

    public static final String PROBLEM_BASE_URL = "https://www.jhipster.tech/problem";
    public static final String INVALID_MFA_TYPE = PROBLEM_BASE_URL + "/invalid-mfa";

    public static final URI DEFAULT_TYPE = URI.create(PROBLEM_BASE_URL + "/problem-with-message");

    public static final URI CONSTRAINT_VIOLATION_TYPE = URI.create(PROBLEM_BASE_URL + "/constraint-violation");

    public static final URI INVALID_PASSWORD_TYPE = URI.create(PROBLEM_BASE_URL + "/invalid-password");

    public static final URI EMAIL_ALREADY_USED_TYPE = URI.create(PROBLEM_BASE_URL + "/email-already-used");

    public static final URI LOGIN_ALREADY_USED_TYPE = URI.create(PROBLEM_BASE_URL + "/login-already-used");

    public static final URI ACCESS_TOKEN_EXPIRED_TYPE = URI.create(PROBLEM_BASE_URL + "/access-token-expired");

    private ErrorConstants() {
    }
}
