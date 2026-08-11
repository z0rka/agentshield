package io.agentshield.controlplane.scan.domain;

import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

/**
 * The scan lifecycle, and the only legal moves between its states.
 *
 * <p>Transitions are enforced here, not trusted from the engine. The engine reports
 * progress over Kafka, where messages arrive late, out of order and more than once - so a
 * {@code RUNNING} event overtaking a {@code COMPLETED} one is normal, not exceptional. Without
 * a guard that late message would resurrect a finished scan, and the CI job waiting on it
 * would hang forever.
 */
public enum ScanStatus {

    CREATED,
    QUEUED,
    DISCOVERING,
    RUNNING,
    EVALUATING,
    COMPLETED,
    FAILED,
    CANCELLED;

    private static final Set<ScanStatus> TERMINAL = EnumSet.of(COMPLETED, FAILED, CANCELLED);

    private static final Map<ScanStatus, Set<ScanStatus>> ALLOWED = Map.of(
            CREATED, EnumSet.of(QUEUED, CANCELLED, FAILED),
            QUEUED, EnumSet.of(DISCOVERING, RUNNING, CANCELLED, FAILED),
            DISCOVERING, EnumSet.of(RUNNING, CANCELLED, FAILED),
            RUNNING, EnumSet.of(EVALUATING, COMPLETED, CANCELLED, FAILED),
            EVALUATING, EnumSet.of(COMPLETED, CANCELLED, FAILED),
            COMPLETED, EnumSet.noneOf(ScanStatus.class),
            FAILED, EnumSet.noneOf(ScanStatus.class),
            CANCELLED, EnumSet.noneOf(ScanStatus.class));

    public boolean isTerminal() {
        return TERMINAL.contains(this);
    }

    public boolean canTransitionTo(ScanStatus next) {
        return ALLOWED.getOrDefault(this, EnumSet.noneOf(ScanStatus.class)).contains(next);
    }

    /** True while new attack scenarios may still be dispatched. */
    public boolean acceptsWork() {
        return this == QUEUED || this == DISCOVERING || this == RUNNING;
    }
}
