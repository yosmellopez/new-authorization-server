package com.pichincha.authorizationserver.web.rest.errors;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.ErrorResponseException;

import java.io.Serial;
import java.net.URI;

public class InvalidPasswordException extends ErrorResponseException {
    @Serial
    private static final long serialVersionUID = 1L;


    public InvalidPasswordException() {
        super(HttpStatus.BAD_REQUEST, ProblemDetailWithCause.ProblemDetailWithCauseBuilder.instance()
                .withStatus(HttpStatus.BAD_REQUEST.value())
                .withType(ErrorConstants.INVALID_PASSWORD_TYPE)
                .withTitle("Incorrect password")
                .build(), null);
    }

    public InvalidPasswordException(URI type, ProblemDetail problemDetail) {
        super(HttpStatus.BAD_REQUEST, problemDetail, null);
    }

    public ProblemDetailWithCause getProblemDetailWithCause() {
        return (ProblemDetailWithCause) this.getBody();
    }
}
