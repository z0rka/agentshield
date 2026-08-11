package io.agentshield.controlplane.shared.error;

import java.io.Serial;

/** A downstream dependency - the security engine, a target - could not be reached. */
public class DependencyUnavailableException extends ControlPlaneException {

    @Serial
    private static final long serialVersionUID = 1L;

    public DependencyUnavailableException(String message) {
        super("dependency_unavailable", message);
    }

    public DependencyUnavailableException(String message, Throwable cause) {
        super("dependency_unavailable", message, cause);
    }
}
