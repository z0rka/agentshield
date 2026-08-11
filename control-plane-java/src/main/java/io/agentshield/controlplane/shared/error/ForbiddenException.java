package io.agentshield.controlplane.shared.error;

import java.io.Serial;

/** The caller is authenticated but lacks the permission the operation requires. */
public class ForbiddenException extends ControlPlaneException {

    @Serial
    private static final long serialVersionUID = 1L;

    public ForbiddenException(String message) {
        super("forbidden", message);
    }
}
