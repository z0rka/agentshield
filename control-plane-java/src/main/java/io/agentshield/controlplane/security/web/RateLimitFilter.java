package io.agentshield.controlplane.security.web;

import io.agentshield.controlplane.security.domain.Principal;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A per-principal request ceiling.
 *
 * <p>Runs after authentication, and that ordering is the design. Limiting by IP would count
 * every CI runner behind one NAT as a single caller and let a token with a bug spend a whole
 * office's budget; limiting by principal makes the noisy caller pay for its own noise.
 *
 * <p><b>Not the concurrency limit.</b> {@code ScanService} already caps scans in flight per
 * workspace and per target, which protects the *targets*. This protects the control plane
 * itself: a client retrying {@code GET /api/scans/{id}} in a tight loop consumes database
 * connections whether or not any scan is running.
 *
 * <p><b>What this is not.</b> A fixed window in process memory. Two replicas therefore allow
 * twice the limit, and a caller can spend a full window's worth on a boundary. Both are
 * acceptable for a ceiling whose job is to stop a runaway loop, and neither would be
 * acceptable for billing or for a security control - a distributed limiter belongs in Redis or
 * at the load balancer, and pretending an in-memory counter is one would be the kind of claim
 * this repository has had to take back before.
 */
@Component
@Order(RateLimitFilter.ORDER)
public class RateLimitFilter extends OncePerRequestFilter {

    /** After {@link ApiAuthenticationFilter}: there is no principal to limit before it runs. */
    public static final int ORDER = 20;

    public static final String LIMIT_HEADER = "X-RateLimit-Limit";
    public static final String REMAINING_HEADER = "X-RateLimit-Remaining";
    public static final String RETRY_AFTER_HEADER = "Retry-After";

    private static final Logger log = LoggerFactory.getLogger(RateLimitFilter.class);

    private final int limit;
    private final Duration window;
    private final Map<String, Window> windows = new ConcurrentHashMap<>();

    public RateLimitFilter(
            @Value("${agentshield.ratelimit.requests-per-minute:300}") int limit,
            @Value("${agentshield.ratelimit.window-seconds:60}") long windowSeconds) {
        this.limit = limit;
        this.window = Duration.ofSeconds(windowSeconds);
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String key = principalKey();
        if (key == null) {
            // Unauthenticated requests are rejected by Spring Security a moment later. Counting
            // them here would let an anonymous caller exhaust a bucket belonging to nobody.
            chain.doFilter(request, response);
            return;
        }

        Window bucket = windows.compute(key, (ignored, existing) ->
                existing == null || existing.isExpired(window) ? new Window() : existing);
        int used = bucket.count.incrementAndGet();

        response.setHeader(LIMIT_HEADER, String.valueOf(limit));
        response.setHeader(REMAINING_HEADER, String.valueOf(Math.max(0, limit - used)));

        if (used > limit) {
            long retryAfter = Math.max(1, window.minus(bucket.age()).toSeconds());
            response.setHeader(RETRY_AFTER_HEADER, String.valueOf(retryAfter));
            response.sendError(429, "rate limit exceeded");
            log.warn("rate limit exceeded for {} ({} requests in the window)", key, used);
            return;
        }

        chain.doFilter(request, response);
        evictExpired();
    }

    private String principalKey() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getPrincipal() instanceof Principal principal)) {
            return null;
        }
        // Workspace *and* user: one member hammering the API must not lock out their colleagues,
        // and a machine token gets its own bucket for the same reason.
        return principal.workspaceId() + ":" + principal.userId();
    }

    /**
     * Drop windows nobody is using.
     *
     * <p>Without this the map grows one entry per principal that ever called and never shrinks,
     * which is a memory leak with a slow fuse - invisible in a demo, fatal after a month.
     */
    private void evictExpired() {
        if (windows.size() < 1024) {
            return;
        }
        windows.values().removeIf(entry -> entry.isExpired(window));
    }

    private static final class Window {
        private final Instant startedAt = Instant.now();
        private final AtomicInteger count = new AtomicInteger();

        Duration age() {
            return Duration.between(startedAt, Instant.now());
        }

        boolean isExpired(Duration window) {
            return age().compareTo(window) >= 0;
        }
    }
}
