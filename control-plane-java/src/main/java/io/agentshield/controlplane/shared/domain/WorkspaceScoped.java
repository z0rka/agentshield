package io.agentshield.controlplane.shared.domain;

import java.util.UUID;

/**
 * An entity that belongs to exactly one workspace.
 *
 * <p>Implemented by every tenant-scoped aggregate so the ownership check can be written once,
 * generically, in {@code security.access.AccessGuard#requireVisible}. Before this existed each
 * call site passed the workspace id by hand:
 *
 * <pre>{@code principal.requireSameWorkspace(target.getWorkspaceId(), "target", id);}</pre>
 *
 * which is a check that compiles perfectly well when you forget it, pass the wrong id, or pass
 * the id of the entity you loaded a moment ago instead of this one. Making the entity supply
 * its own owner removes that whole class of mistake.
 */
public interface WorkspaceScoped {

    UUID getWorkspaceId();
}
