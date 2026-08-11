package io.agentshield.controlplane.security.domain;

/**
 * What a caller is allowed to do, independent of which role grants it.
 *
 * <p>Services depend on permissions over on roles. That way adding a role - an auditor
 * who may read findings but not targets, say - is a change to {@link Role} alone and touches
 * no call site.
 */
public enum Permission {

    /** Read any resource in the workspace. */
    READ,

    /** Create or modify targets, policies and findings. */
    WRITE,

    /**
     * Start, cancel or re-run a scan.
     *
     * <p>Separate from {@link #WRITE} on purpose: a scan generates adversarial traffic against
     * a real system, so "may edit configuration" and "may fire attacks" are not the same
     * authority.
     */
    RUN_SCAN,

    /** Manage membership, CI tokens and deletion. */
    ADMINISTER
}
