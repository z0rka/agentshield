package io.agentshield.controlplane.shared.error;

import java.io.Serial;

/**
 * The request is well-formed but semantically invalid.
 *
 * <p>Distinct from bean-validation failures, which never reach application code: this is for
 * rules that need context, such as a target and a policy belonging to different projects.
 */
public class InvalidRequestException extends ControlPlaneException {

    @Serial
    private static final long serialVersionUID = 1L;

    public InvalidRequestException(String message) {
        super("invalid_request", message);
    }

    public InvalidRequestException(String message, Throwable cause) {
        super("invalid_request", message, cause);
    }
}
