package io.agentshield.controlplane.shared.error;

import java.io.Serial;

/**
 * The request conflicts with current state.
 *
 * <p>Raised by aggregates as well as services - cancelling a completed scan is a conflict
 * decided by {@code Scan}, not by a controller.
 */
public class ConflictException extends ControlPlaneException {

    @Serial
    private static final long serialVersionUID = 1L;

    public ConflictException(String message) {
        super("conflict", message);
    }
}
