package io.agentshield.controlplane.security.access;

import io.agentshield.controlplane.security.domain.Principal;

import java.util.Optional;
import java.util.function.Supplier;

/**
 * Supplies the caller for the current unit of work.
 *
 * <p>An interface, not a static lookup, so the source of the principal is a
 * declared, replaceable dependency. In an HTTP request it comes from the Spring Security
 * context; in a test it comes from a fixed value; in a future Kafka-driven command handler it
 * would come from the message. None of the callers need to change for that.
 */
public interface PrincipalProvider {

    Optional<Principal> currentPrincipal();

    /**
     * Run {@code work} as {@code principal}, then restore whatever was there before.
     *
     * <p>For the scheduler, which creates work with no human in the request path and still has
     * to go through the same authorisation, concurrency and audit checks as a person. The
     * alternative - a privileged entry point into {@code ScanService} that skips the guard - is
     * a second API with weaker rules, and the weaker one is the one that gets exploited.
     *
     * <p>The previous context is restored in a {@code finally}, because a pooled thread that
     * keeps an elevated principal after the work returns is a privilege escalation waiting for
     * the next request that lands on it.
     */
    <T> T callAs(Principal principal, Supplier<T> work);
}
