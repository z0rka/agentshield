package io.agentshield.controlplane.security.domain;

import java.util.UUID;

/**
 * The authenticated caller and the workspace they are acting in.
 *
 * <p>A pure value object: it answers questions about identity and holds no reference to the
 * framework. It used to expose {@code Principal.current()}, reaching into
 * {@code SecurityContextHolder} from anywhere - which made the security context an invisible
 * global dependency of every service, and made those services impossible to unit-test without
 * standing one up. Obtaining the principal is now the job of
 * {@code security.access.PrincipalProvider}, and enforcing anything with it is the job of
 * {@code security.access.AccessGuard}.
 *
 * <p>The workspace comes from the authenticated context and nowhere else. It is never read
 * from a path variable, query parameter or header: any of those would let a caller name a
 * workspace they do not belong to and rely on a later check to catch it.
 */
public record Principal(UUID userId, String email, UUID workspaceId, Role role, boolean machine) {

    /** A CI token acting on behalf of a workspace, with no human user attached. */
    public static Principal forCiToken(UUID workspaceId, UUID tokenId) {
        return new Principal(tokenId, "ci-token", workspaceId, Role.ENGINEER, true);
    }

    public boolean can(Permission permission) {
        return role.can(permission);
    }

    public boolean ownsWorkspace(UUID candidateWorkspaceId) {
        return workspaceId.equals(candidateWorkspaceId);
    }
}
