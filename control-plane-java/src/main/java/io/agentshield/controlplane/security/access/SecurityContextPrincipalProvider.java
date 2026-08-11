package io.agentshield.controlplane.security.access;

import io.agentshield.controlplane.security.domain.Principal;

import java.util.Optional;
import java.util.function.Supplier;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

/**
 * Reads the caller from the Spring Security context.
 *
 * <p>The one place in the application that touches {@code SecurityContextHolder}. Everything
 * else depends on {@link PrincipalProvider}, so the framework coupling is a single class
 * rather than a static call scattered through every service.
 */
@Component
public class SecurityContextPrincipalProvider implements PrincipalProvider {

    @Override
    public Optional<Principal> currentPrincipal() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return Optional.empty();
        }
        return authentication.getPrincipal() instanceof Principal principal
                ? Optional.of(principal)
                : Optional.empty();
    }

    @Override
    public <T> T callAs(Principal principal, Supplier<T> work) {
        var previous = SecurityContextHolder.getContext().getAuthentication();
        var authentication = new UsernamePasswordAuthenticationToken(
                principal, null, java.util.List.of(new SimpleGrantedAuthority(principal.role().authority())));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        try {
            return work.get();
        } finally {
            // Restored even when the work throws. This runs on a pooled scheduler thread, and
            // a thread that keeps an elevated principal is a privilege escalation waiting for
            // whatever lands on it next.
            SecurityContextHolder.getContext().setAuthentication(previous);
        }
    }
}
