package io.agentshield.controlplane.shared.error;

import java.io.Serial;

/**
 * Base class for failures the application raises intentionally.
 *
 * <p>Carries a stable machine-readable {@link #errorCode()} and nothing else. In particular it
 * does <em>not</em> carry an HTTP status: domain and application code should be able to say
 * "this conflicts with current state" without knowing that anyone is speaking HTTP. Mapping a
 * code onto a status is a presentation concern and lives in
 * {@code shared.web.GlobalExceptionHandler}.
 *
 * <p>That separation is what lets {@code Scan.transitionTo} reject an illegal move without the
 * scan aggregate importing {@code HttpStatus}, and it is why the same services can later be
 * driven by a Kafka consumer or a CLI without dragging the servlet stack along.
 *
 * <p>The code is part of the API contract: a CI client needs to tell "your policy is invalid"
 * from "this scan is already running" without parsing English.
 */
public abstract class ControlPlaneException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 1L;

    private final String errorCode;

    protected ControlPlaneException(String errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    protected ControlPlaneException(String errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public String errorCode() {
        return errorCode;
    }
}
