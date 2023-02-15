package org.ylplabs.usersservice.web.rest.errors;

import jakarta.annotation.Nullable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.ErrorResponseException;

import java.net.URI;

public class UnauthorizedException extends ErrorResponseException {

    public UnauthorizedException(@Nullable URI type, @Nullable String title) {
        this(type, title, "error.unauthorized", null);
    }

    public UnauthorizedException(URI type, String defaultMessage, String entityName, String errorKey) {
        super(HttpStatus.UNAUTHORIZED, ProblemDetailWithCause.ProblemDetailWithCauseBuilder.instance()
                .withStatus(HttpStatus.UNAUTHORIZED.value())
                .withType(type)
                .withTitle(defaultMessage)
                .withProperty("message", "error." + errorKey)
                .withProperty("params", entityName)
                .build(), null);
    }

    public UnauthorizedException(ProblemDetail exception) {
        super(HttpStatus.UNAUTHORIZED, exception, null);
    }

    public ProblemDetailWithCause getProblemDetailWithCause() {
        ProblemDetail problemDetail = this.getBody();
        if (problemDetail instanceof ProblemDetailWithCause cause)
            return cause;
        return ProblemDetailWithCause.ProblemDetailWithCauseBuilder.instance()
                .withStatus(problemDetail.getStatus())
                .withType(problemDetail.getType())
                .withTitle(problemDetail.getTitle())
                .withDetail(problemDetail.getDetail())
                .build();
    }
}
