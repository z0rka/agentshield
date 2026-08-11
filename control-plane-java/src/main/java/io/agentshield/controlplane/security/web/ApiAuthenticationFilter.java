package io.agentshield.controlplane.security.web;

import io.agentshield.controlplane.security.application.AuthenticationService;
import io.agentshield.controlplane.security.domain.Principal;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Resolves the caller into a {@link Principal}.
 *
 * <p>Two credential types, one code path: a human's Basic credentials, or a CI token in
 * {@code X-AgentShield-Token}. Both produce a principal carrying the workspace and role, so
 * every downstream authorisation check looks the same regardless of who is calling. The
 * alternative - a separate machine API with its own checks - is how machine surfaces end up
 * with weaker authorisation than the human one.
 */
@Component
public class ApiAuthenticationFilter extends OncePerRequestFilter {

    public static final String CI_TOKEN_HEADER = "X-AgentShield-Token";

    private static final Logger log = LoggerFactory.getLogger(ApiAuthenticationFilter.class);

    private final AuthenticationService authentication;

    public ApiAuthenticationFilter(AuthenticationService authentication) {
        this.authentication = authentication;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            resolve(request).ifPresent(ApiAuthenticationFilter::authenticate);
        }
        chain.doFilter(request, response);
    }

    private Optional<Principal> resolve(HttpServletRequest request) {
        String ciToken = request.getHeader(CI_TOKEN_HEADER);
        if (ciToken != null && !ciToken.isBlank()) {
            return authentication.authenticateCiToken(ciToken);
        }

        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Basic ")) {
            return Optional.empty();
        }
        try {
            String decoded = new String(
                    Base64.getDecoder().decode(header.substring("Basic ".length())),
                    StandardCharsets.UTF_8);
            int separator = decoded.indexOf(':');
            if (separator < 0) {
                return Optional.empty();
            }
            return authentication.authenticateUser(
                    decoded.substring(0, separator), decoded.substring(separator + 1));
        } catch (IllegalArgumentException exception) {
            // Malformed header: treated as anonymous, not as an error, so a broken client
            // gets a 401 and not a 500 that looks like a server fault.
            log.debug("malformed Authorization header");
            return Optional.empty();
        }
    }

    private static void authenticate(Principal principal) {
        var authorities = List.of(new SimpleGrantedAuthority(principal.role().authority()));
        var token = UsernamePasswordAuthenticationToken.authenticated(principal, null, authorities);
        SecurityContextHolder.getContext().setAuthentication(token);
    }
}
