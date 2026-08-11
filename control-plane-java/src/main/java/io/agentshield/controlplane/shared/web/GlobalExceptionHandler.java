package io.agentshield.controlplane.shared.web;

import io.agentshield.controlplane.shared.error.ConflictException;
import io.agentshield.controlplane.shared.error.ControlPlaneException;
import io.agentshield.controlplane.shared.error.DependencyUnavailableException;
import io.agentshield.controlplane.shared.error.ForbiddenException;
import io.agentshield.controlplane.shared.error.InvalidRequestException;
import io.agentshield.controlplane.shared.error.NotFoundException;

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Translates application failures into HTTP.
 *
 * <p>This is the only place that knows an exception type has a status code. Keeping the
 * mapping here over on the exceptions themselves is what lets the domain raise
 * {@link ConflictException} without importing anything from the servlet stack.
 *
 * <p>Error bodies never echo internal detail. A stack trace or a SQL message in a 500 tells an
 * attacker the schema, the ORM and the framework version; the log keeps the real cause.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    /** Exception type to status. Adding an exception without an entry here is a 500 by default. */
    private static final Map<Class<? extends ControlPlaneException>, HttpStatus> STATUSES = Map.of(
            NotFoundException.class, HttpStatus.NOT_FOUND,
            ForbiddenException.class, HttpStatus.FORBIDDEN,
            ConflictException.class, HttpStatus.CONFLICT,
            InvalidRequestException.class, HttpStatus.BAD_REQUEST,
            DependencyUnavailableException.class, HttpStatus.SERVICE_UNAVAILABLE);

    @ExceptionHandler(ControlPlaneException.class)
    public ResponseEntity<ApiError> handleControlPlane(
            ControlPlaneException exception, HttpServletRequest request) {

        var status = STATUSES.getOrDefault(exception.getClass(), HttpStatus.INTERNAL_SERVER_ERROR);
        if (status == HttpStatus.INTERNAL_SERVER_ERROR) {
            // An unmapped application exception is a programming error, not a client error.
            log.error("no status mapping for {}", exception.getClass().getName(), exception);
        }
        return ResponseEntity.status(status)
                .body(ApiError.of(exception.errorCode(), exception.getMessage(),
                        request.getRequestURI()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> handleValidation(
            MethodArgumentNotValidException exception, HttpServletRequest request) {

        List<String> details = exception.getBindingResult().getFieldErrors().stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .toList();
        return ResponseEntity.badRequest()
                .body(ApiError.of("validation_failed", "the request body is not valid",
                        details, request.getRequestURI()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleUnexpected(
            Exception exception, HttpServletRequest request) {

        log.error("unhandled exception on {}", request.getRequestURI(), exception);
        return ResponseEntity.internalServerError()
                .body(ApiError.of("internal_error", "the request could not be completed",
                        request.getRequestURI()));
    }
}
