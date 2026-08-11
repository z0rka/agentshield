package io.agentshield.controlplane.shared.error;

import java.io.Serial;

/**
 * The resource does not exist, or the caller's workspace cannot see it.
 *
 * <p>Deliberately the same failure in both cases. Distinguishing "exists but is not yours"
 * from "does not exist" turns the API into an oracle for enumerating other tenants' resource
 * ids, so cross-workspace access is reported as absence - see
 * {@code security.access.AccessGuard#requireSameWorkspace}.
 */
public class NotFoundException extends ControlPlaneException {

    @Serial
    private static final long serialVersionUID = 1L;

    public NotFoundException(String resource, Object id) {
        super("not_found", resource + " " + id + " was not found");
    }

    public NotFoundException(String message) {
        super("not_found", message);
    }
}
