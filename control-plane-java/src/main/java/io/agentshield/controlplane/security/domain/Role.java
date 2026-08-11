package io.agentshield.controlplane.security.domain;

import java.util.Set;

/**
 * Workspace roles, defined as the set of permissions each grants.
 *
 * <p>A Viewer must never be able to start a scan: scans generate adversarial traffic against a
 * real system, and "read-only" has to mean it.
 */
public enum Role {

    /** Reads reports. Changes nothing, runs nothing. */
    VIEWER(Set.of(Permission.READ)),

    /** Creates targets and policies, runs scans, manages findings. */
    ENGINEER(Set.of(Permission.READ, Permission.WRITE, Permission.RUN_SCAN)),

    /** Everything, plus membership, deletion and CI tokens. */
    OWNER(Set.of(Permission.READ, Permission.WRITE, Permission.RUN_SCAN, Permission.ADMINISTER));

    private final Set<Permission> permissions;

    Role(Set<Permission> permissions) {
        this.permissions = Set.copyOf(permissions);
    }

    public boolean can(Permission permission) {
        return permissions.contains(permission);
    }

    public Set<Permission> permissions() {
        return permissions;
    }

    /** Spring Security authority name for this role. */
    public String authority() {
        return "ROLE_" + name();
    }
}
