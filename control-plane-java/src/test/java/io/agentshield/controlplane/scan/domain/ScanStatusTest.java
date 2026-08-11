package io.agentshield.controlplane.scan.domain;

import io.agentshield.controlplane.scan.domain.Scan;
import io.agentshield.controlplane.scan.domain.ScanStatus;
import io.agentshield.controlplane.shared.error.ConflictException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * The transition guard.
 *
 * <p>These are the rules that keep a late Kafka message from resurrecting a finished scan.
 * Worth unit-testing because the failure mode - a CI job hanging on a scan that already
 * completed - is invisible until someone waits twenty minutes for it.
 */
class ScanStatusTest {

    @Test
    @DisplayName("terminal states accept no further transitions")
    void terminalStatesAreFinal() {
        for (ScanStatus terminal : new ScanStatus[] {
                ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED}) {
            for (ScanStatus next : ScanStatus.values()) {
                assertThat(terminal.canTransitionTo(next))
                        .as("%s -> %s must be rejected", terminal, next)
                        .isFalse();
            }
        }
    }

    @ParameterizedTest
    @EnumSource(ScanStatus.class)
    @DisplayName("every non-terminal state can still fail")
    void anythingRunningCanFail(ScanStatus status) {
        if (status.isTerminal()) {
            return;
        }
        assertThat(status.canTransitionTo(ScanStatus.FAILED)).isTrue();
        assertThat(status.canTransitionTo(ScanStatus.CANCELLED)).isTrue();
    }

    @Test
    @DisplayName("a repeated status is accepted as a no-op, not rejected")
    void duplicateStatusIsIdempotent() {
        var scan = newScan();
        scan.transitionTo(ScanStatus.QUEUED);

        assertThat(scan.tryTransitionTo(ScanStatus.QUEUED)).isTrue();
        assertThat(scan.getStatus()).isEqualTo(ScanStatus.QUEUED);
    }

    @Test
    @DisplayName("an out-of-order engine event cannot reopen a completed scan")
    void lateEventCannotReopenCompletedScan() {
        var scan = newScan();
        scan.transitionTo(ScanStatus.QUEUED);
        scan.transitionTo(ScanStatus.RUNNING);
        scan.transitionTo(ScanStatus.COMPLETED);

        // Kafka redelivers an older RUNNING event after the scan already finished.
        assertThat(scan.tryTransitionTo(ScanStatus.RUNNING)).isFalse();
        assertThat(scan.getStatus()).isEqualTo(ScanStatus.COMPLETED);
    }

    @Test
    @DisplayName("cancelling a completed scan is a client error, not a silent no-op")
    void cancellingCompletedScanConflicts() {
        var scan = newScan();
        scan.transitionTo(ScanStatus.QUEUED);
        scan.transitionTo(ScanStatus.RUNNING);
        scan.transitionTo(ScanStatus.COMPLETED);

        assertThatThrownBy(() -> scan.transitionTo(ScanStatus.CANCELLED))
                .isInstanceOf(ConflictException.class);
    }

    @Test
    @DisplayName("startedAt is set once, on the first move to RUNNING")
    void startedAtIsStable() {
        var scan = newScan();
        scan.transitionTo(ScanStatus.QUEUED);
        scan.transitionTo(ScanStatus.RUNNING);
        var firstStart = scan.getStartedAt();

        scan.tryTransitionTo(ScanStatus.EVALUATING);
        scan.tryTransitionTo(ScanStatus.COMPLETED);

        assertThat(scan.getStartedAt()).isEqualTo(firstStart);
        assertThat(scan.getCompletedAt()).isNotNull();
    }

    private static Scan newScan() {
        return new Scan(
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                "key",
                "correlation");
    }
}
