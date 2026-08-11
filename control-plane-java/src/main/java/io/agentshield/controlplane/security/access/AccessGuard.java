package io.agentshield.controlplane.security.access;

import io.agentshield.controlplane.security.domain.Permission;
import io.agentshield.controlplane.security.domain.Principal;
import io.agentshield.controlplane.shared.domain.WorkspaceScoped;
import io.agentshield.controlplane.shared.error.ForbiddenException;
import io.agentshield.controlplane.shared.error.NotFoundException;

import java.util.Collection;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * The single entry point for "may this caller do this?".
 *
 * <p>Injected, not static. Every service that needs authorisation declares it in its
 * constructor, which means the dependency is visible, mockable, and impossible to acquire by
 * accident from deep inside a helper.
 *
 * <p>Two rules are enforced here over restated at each call site:
 *
 * <ul>
 *   <li><b>Permission before work.</b> {@link #require(Permission)} returns the principal, so
 *       the check and the subsequent use of {@code workspaceId()} cannot drift apart.
 *   <li><b>Ownership on read.</b> {@link #requireVisible} reports a resource from another
 *       workspace as <em>absent</em>, never as forbidden. Distinguishing the two would turn
 *       the API into an oracle for enumerating other tenants' resource ids.
 * </ul>
 */
@Component
public class AccessGuard {

    private final PrincipalProvider principals;

    public AccessGuard(PrincipalProvider principals) {
        this.principals = principals;
    }

    /**
     * The caller.
     *
     * @throws ForbiddenException when the request is unauthenticated. Reaching application code
     *     without a principal is a routing bug, and failing closed is the only safe response.
     */
    public Principal principal() {
        return principals.currentPrincipal()
                .orElseThrow(() -> new ForbiddenException("no authenticated principal for this request"));
    }

    /** The workspace every query in this unit of work must be scoped to. */
    public UUID workspaceId() {
        return principal().workspaceId();
    }

    /** Asserts the permission and returns the caller, so callers need only one lookup. */
    public Principal require(Permission permission) {
        var principal = principal();
        if (!principal.can(permission)) {
            throw new ForbiddenException(
                    "role " + principal.role() + " does not permit " + permission);
        }
        return principal;
    }

    /**
     * Asserts the entity belongs to the caller's workspace, and returns it.
     *
     * <p>Written to be used inline at the point of load, so the unchecked entity never gets a
     * name in the calling method:
     *
     * <pre>{@code
     * return access.requireVisible(
     *         targets.findById(id).orElseThrow(() -> new NotFoundException("target", id)),
     *         "target", id);
     * }</pre>
     */
    public <T extends WorkspaceScoped> T requireVisible(T entity, String resource, Object id) {
        if (!principal().ownsWorkspace(entity.getWorkspaceId())) {
            throw new NotFoundException(resource, id);
        }
        return entity;
    }

    /** Ownership check for a collection, for endpoints that load several entities at once. */
    public <T extends WorkspaceScoped> List<T> requireAllVisible(
            Collection<T> entities, String resource) {

        var workspace = workspaceId();
        return entities.stream()
                .map(entity -> {
                    if (!workspace.equals(entity.getWorkspaceId())) {
                        throw new NotFoundException(resource, "?");
                    }
                    return entity;
                })
                .toList();
    }
}
