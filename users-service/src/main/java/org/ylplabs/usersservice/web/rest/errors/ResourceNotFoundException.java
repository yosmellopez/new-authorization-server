package org.ylplabs.usersservice.web.rest.errors;

import org.springframework.http.HttpStatus;
import org.springframework.lang.Nullable;
import org.springframework.web.ErrorResponseException;

import java.net.URI;

public class ResourceNotFoundException extends ErrorResponseException {


    public ResourceNotFoundException(@Nullable URI type, @Nullable String title, @Nullable String detail) {
        this(type, title, HttpStatus.NOT_FOUND, detail);
    }

    public ResourceNotFoundException(URI type, String defaultMessage, HttpStatus status, String errorKey) {
        super(status, ProblemDetailWithCause.ProblemDetailWithCauseBuilder.instance()
            .withStatus(status.value())
            .withType(type)
            .withTitle(defaultMessage)
            .withProperty("message", "error." + errorKey)
            .withProperty("params", errorKey)
            .build(), null);
    }
}
