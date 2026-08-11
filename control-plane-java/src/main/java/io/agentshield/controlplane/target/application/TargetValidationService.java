package io.agentshield.controlplane.target.application;

import io.agentshield.controlplane.engine.application.EngineClient;
import io.agentshield.controlplane.security.access.AccessGuard;
import io.agentshield.controlplane.security.domain.Permission;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Checks that a target is reachable and reports what it advertises.
 *
 * <p>Runs no attacks. Operators need to confirm connectivity and credentials without
 * generating adversarial traffic - otherwise the first thing they learn about a misconfigured
 * target is a page of findings caused by their own typo.
 *
 * <p>A service rather than logic in the controller. Validation decrypts the target
 * configuration and calls out to the engine, which is a decision about authority and a
 * dependency on another system: neither belongs in a class whose job is turning HTTP into
 * method calls. Keeping it here also means a future CLI or scheduled re-validation gets the
 * same permission check for free.
 */
@Service
public class TargetValidationService {

    /** Outcome of a connectivity check, in domain terms over HTTP terms. */
    public record ValidationResult(
            boolean reachable,
            String adapterType,
            List<String> discoveredTools,
            List<String> warnings,
            String message) {
    }

    private final TargetService targets;
    private final EngineClient engine;
    private final AccessGuard access;

    public TargetValidationService(
            TargetService targets, EngineClient engine, AccessGuard access) {
        this.targets = targets;
        this.engine = engine;
        this.access = access;
    }

    @Transactional(readOnly = true)
    public ValidationResult validate(UUID targetId) {
        access.require(Permission.WRITE);
        var target = targets.require(targetId);

        var discovery = engine.discover(targets.engineConfiguration(target));
        return new ValidationResult(
                true,
                target.getAdapterType(),
                discovery.tools(),
                discovery.warnings(),
                "target is reachable");
    }
}
