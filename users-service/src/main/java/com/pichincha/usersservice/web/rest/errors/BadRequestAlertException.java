package com.pichincha.usersservice.web.rest.errors;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.ErrorResponseException;

import java.io.Serial;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class BadRequestAlertException extends ErrorResponseException {

    @Serial
    private static final long serialVersionUID = 1L;

    public BadRequestAlertException(String defaultMessage, String entityName, String errorKey) {
        this(ErrorConstants.DEFAULT_TYPE, defaultMessage, entityName, errorKey);
    }

    public BadRequestAlertException(URI type, String defaultMessage, String entityName, String errorKey) {
        super(HttpStatus.BAD_REQUEST, ProblemDetailWithCause.ProblemDetailWithCauseBuilder.instance()
                .withStatus(HttpStatus.BAD_REQUEST.value())
                .withType(type)
                .withTitle(defaultMessage)
                .withProperty("message", "error." + errorKey)
                .withProperty("params", entityName)
                .build(), null);
    }

    public BadRequestAlertException(ProblemDetail problemDetail) {
        super(HttpStatus.BAD_REQUEST, problemDetail, null);
    }

    public ProblemDetailWithCause getProblemDetailWithCause() {
        ProblemDetail problemDetail = this.getBody();
        if (problemDetail instanceof ProblemDetailWithCause cause)
            return cause;
        Map<String, Object> properties = Optional.ofNullable(problemDetail.getProperties()).orElse(new HashMap<>());
        return ProblemDetailWithCause.ProblemDetailWithCauseBuilder.instance()
                .withStatus(problemDetail.getStatus())
                .withType(problemDetail.getType())
                .withTitle(problemDetail.getTitle())
                .withDetail(problemDetail.getDetail())
                .withProperties(properties)
                .build();
    }
}
