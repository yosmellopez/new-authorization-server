package org.ylplabs.usersservice.web.rest.errors;

import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.StringUtils;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConversionException;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.ErrorResponse;
import org.springframework.web.ErrorResponseException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;
import org.ylplabs.usersservice.service.util.HeaderUtil;

import java.net.URI;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import static org.springframework.core.annotation.AnnotatedElementUtils.findMergedAnnotation;

/**
 * Controller advice to translate the server side exceptions to client-friendly json structures.
 * The error response follows RFC7807 - Problem Details for HTTP APIs (<a href="https://tools.ietf.org/html/rfc7807">...</a>).
 */
@ControllerAdvice
public class ExceptionTranslator extends ResponseEntityExceptionHandler {

    private static final String FIELD_ERRORS_KEY = "fieldErrors";
    private static final String MESSAGE_KEY = "message";
    private static final String PATH_KEY = "path";

    private final Environment env;

    public ExceptionTranslator(Environment env) {
        this.env = env;
    }

    @ExceptionHandler
    public ResponseEntity<Object> handleAnyException(Throwable ex, NativeWebRequest request) {
        ProblemDetailWithCause pdCause = wrapAndCustomizeProblem(ex, request);
        return handleExceptionInternal((Exception) ex, pdCause, buildHeaders(ex, request), HttpStatusCode.valueOf(pdCause.getStatus()), request);
    }

    @Nullable
    @Override
    protected ResponseEntity<Object> handleExceptionInternal(@NonNull Exception ex, @Nullable Object body,
                                                             @NonNull HttpHeaders headers, @NonNull HttpStatusCode statusCode,
                                                             @NonNull WebRequest request) {
        body = body == null ? wrapAndCustomizeProblem(ex, (NativeWebRequest) request) : body;
        return super.handleExceptionInternal(ex, body, headers, statusCode, request);
    }

    protected ProblemDetailWithCause wrapAndCustomizeProblem(Throwable ex, NativeWebRequest request) {
        return customizeProblem(getProblemDetailWithCause(ex), ex, request);
    }

    private ProblemDetailWithCause getProblemDetailWithCause(Throwable ex) {
        if (ex instanceof UnauthorizedException exception)
            return exception.getProblemDetailWithCause();
        if (ex instanceof BadRequestAlertException exception)
            return exception.getProblemDetailWithCause();
        if (ex instanceof ResourceNotFoundException exception)
            return (ProblemDetailWithCause) exception.getBody();
        if (ex instanceof ErrorResponseException exp && exp.getBody() instanceof ProblemDetailWithCause)
            return (ProblemDetailWithCause) exp.getBody();
        return ProblemDetailWithCause.ProblemDetailWithCauseBuilder.instance()
                .withStatus(toStatus(ex).value())
                .build();
    }

    protected ProblemDetailWithCause customizeProblem(ProblemDetailWithCause problem, Throwable err, NativeWebRequest request) {
        if (problem.getStatus() <= 0) problem.setStatus(toStatus(err));

        if (problem.getType().equals(URI.create("about:blank")))
            problem.setType(getMappedType(err));

        // higher precedence to Custom/ResponseStatus types
        if (problem.getTitle() == null) {
            String title = extractTitle(err, problem.getStatus());
            if (!problem.getTitle().equals(title))
                problem.setTitle(title);
        }

        if (problem.getDetail() == null) {
            // higher precedence to cause
            problem.setDetail(getCustomizedErrorDetails(err));
        }

        if (problem.getProperties() == null || !problem.getProperties().containsKey(MESSAGE_KEY))
            problem.setProperty(MESSAGE_KEY,
                    getMappedMessageKey((Throwable) err) != null
                            ? getMappedMessageKey(err)
                            : "error.http." + problem.getStatus());

        if (problem.getProperties() == null || !problem.getProperties().containsKey(PATH_KEY))
            problem.setProperty(PATH_KEY, getPathValue(request));

        if ((err instanceof MethodArgumentNotValidException) &&
                (problem.getProperties() == null || !problem.getProperties().containsKey(FIELD_ERRORS_KEY)))
            problem.setProperty(FIELD_ERRORS_KEY, getFieldErrors((MethodArgumentNotValidException) err));
        problem.setCause(buildCause(err.getCause(), request).orElse(null));
        return problem;
    }

    private String extractTitle(Throwable err, int statusCode) {
        return getCustomizedTitle(err) != null ? getCustomizedTitle(err) : extractTitleForResponseStatus(err, statusCode);
    }

    private List<FieldErrorVM> getFieldErrors(MethodArgumentNotValidException ex) {
        return ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(f ->
                        new FieldErrorVM(
                                f.getObjectName().replaceFirst("dto$", ""),
                                f.getField(),
                                StringUtils.isNotBlank(f.getDefaultMessage()) ? f.getDefaultMessage() : f.getCode()
                        )
                )
                .toList();
    }

    private String extractTitleForResponseStatus(Throwable err, int statusCode) {
        ResponseStatus specialStatus = extractResponseStatus(err);
        return specialStatus == null ? HttpStatus.valueOf(statusCode).getReasonPhrase() : specialStatus.reason();
    }

    private String extractURI(NativeWebRequest request) {
        HttpServletRequest nativeRequest = request.getNativeRequest(HttpServletRequest.class);
        return nativeRequest != null ? nativeRequest.getRequestURI() : StringUtils.EMPTY;
    }

    private String getCustomizedErrorDetails(Throwable err) {
        Collection<String> activeProfiles = Arrays.asList(env.getActiveProfiles());
        if (activeProfiles.contains("prod")) {
            if (err instanceof HttpMessageConversionException) return "Unable to convert http message";
            if (containsPackageName(err.getMessage())) return "Unexpected runtime exception";
        }
        return err.getCause() != null ? err.getCause().getMessage() : err.getMessage();
    }

    private HttpStatus toStatus(final Throwable throwable) {
        // Let the ErrorResponse take this responsibility
        if (throwable instanceof ErrorResponse err) return HttpStatus.valueOf(err.getBody().getStatus());

        return Optional
                .ofNullable(getMappedStatus(throwable))
                .orElse(Optional
                        .ofNullable(resolveResponseStatus(throwable))
                        .map(ResponseStatus::value)
                        .orElse(HttpStatus.INTERNAL_SERVER_ERROR));
    }

    private ResponseStatus extractResponseStatus(final Throwable throwable) {
        return resolveResponseStatus(throwable);
    }

    private HttpStatus getMappedStatus(Throwable err) {
        // Where we disagree with Spring defaults
        if (err instanceof AccessDeniedException accDenied) return HttpStatus.FORBIDDEN;
        if (err instanceof BadCredentialsException) return HttpStatus.UNAUTHORIZED;
        return null;
    }

    private URI getPathValue(NativeWebRequest request) {
        if (request == null) return URI.create("about:blank");
        return URI.create(extractURI((NativeWebRequest) request));
    }

    private ResponseStatus resolveResponseStatus(final Throwable type) {
        final ResponseStatus candidate = findMergedAnnotation(type.getClass(), ResponseStatus.class);
        return candidate == null && type.getCause() != null ? resolveResponseStatus(type.getCause()) : candidate;
    }

    private HttpHeaders buildHeaders(Throwable err, NativeWebRequest request) {
        String applicationName = "user-service";
        return err instanceof BadRequestAlertException ?
                HeaderUtil.createFailureAlert(applicationName, true, ((BadRequestAlertException) err).getBody().getDetail(),
                        ((BadRequestAlertException) err).getBody().getTitle(), ((BadRequestAlertException) err).getMessage()) : null;
    }

    public Optional<ProblemDetailWithCause> buildCause(final Throwable throwable, NativeWebRequest request) {
        if (throwable != null && isCasualChainEnabled()) {
            return Optional.of(customizeProblem(getProblemDetailWithCause(throwable), throwable, request));
        }
        return Optional.empty();
    }

    private boolean isCasualChainEnabled() {
        // Customize as per the needs
        return false;
    }

    private URI getMappedType(Throwable err) {
        if (err instanceof MethodArgumentNotValidException)
            return ErrorConstants.CONSTRAINT_VIOLATION_TYPE;
        return ErrorConstants.DEFAULT_TYPE;
    }

    private String getCustomizedTitle(Throwable err) {
        if (err instanceof MethodArgumentNotValidException)
            return "Method argument not valid";
        return null;
    }

    private String getMappedMessageKey(Throwable err) {
        if (err instanceof MethodArgumentNotValidException)
            return ErrorConstants.ERR_VALIDATION;
        return null;
    }

    private boolean containsPackageName(String message) {

        // This list is for sure not complete
        return StringUtils.containsAny(message, "org.", "java.", "net.", "jakarta.", "javax.", "com.", "io.", "de.",
                "org.ylplabs.investment.web.rest.errors");
    }
}
