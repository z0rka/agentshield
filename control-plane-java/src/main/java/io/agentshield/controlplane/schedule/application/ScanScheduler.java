package io.agentshield.controlplane.schedule.application;

import io.agentshield.controlplane.scan.application.ScanService;
import io.agentshield.controlplane.schedule.domain.ScanSchedule;
import io.agentshield.controlplane.schedule.repository.ScanScheduleRepository;
import io.agentshield.controlplane.security.access.PrincipalProvider;
import io.agentshield.controlplane.security.domain.Principal;
import io.agentshield.controlplane.security.domain.Role;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import java.time.Duration;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Starts the scans nobody is awake to start.
 *
 * <p>The only place in the platform that creates work with no human in the request path, which
 * makes it the only place that needs a principal it was not handed. It builds one for the
 * schedule's workspace with {@code RUN_SCAN} and no more, so a scheduled scan goes through the
 * identical authorisation, concurrency and audit path as a human's - a scheduler with a
 * privileged back door into {@code ScanService} would be a second, weaker API.
 *
 * <p>Refusals are expected and are not errors. A target already being scanned, or disabled,
 * means this run is skipped and the next one deferred; the alternative is a log line every
 * poll saying the same thing.
 */
@Component
public class ScanScheduler {

    private static final Logger log = LoggerFactory.getLogger(ScanScheduler.class);

    /** How long a schedule waits after a refusal. Long enough that the reason usually clears. */
    private static final Duration DEFER_AFTER_REFUSAL = Duration.ofMinutes(5);

    private final ScanScheduleRepository schedules;
    private final ScanService scans;
    private final PrincipalProvider principals;
    private final Counter started;
    private final Counter deferred;
    private final int batchSize;

    public ScanScheduler(
            ScanScheduleRepository schedules,
            ScanService scans,
            PrincipalProvider principals,
            MeterRegistry meters,
            @Value("${agentshield.schedule.batch-size:20}") int batchSize) {
        this.schedules = schedules;
        this.scans = scans;
        this.principals = principals;
        this.batchSize = batchSize;
        this.started = Counter.builder("agentshield.schedule.started").register(meters);
        this.deferred = Counter.builder("agentshield.schedule.deferred").register(meters);
    }

    @Scheduled(fixedDelayString = "${agentshield.schedule.poll-interval-ms:30000}")
    @Transactional
    public void poll() {
        var due = schedules.claimDue(batchSize);
        if (due.isEmpty()) {
            return;
        }

        for (ScanSchedule schedule : due) {
            try {
                UUID scanId = principals.callAs(machinePrincipal(schedule), () ->
                        scans.create(
                                schedule.getProjectId(),
                                schedule.getTargetId(),
                                schedule.getPolicyId(),
                                schedule.getSuites(),
                                schedule.getMaxScenarios(),
                                0,
                                // Deterministic per due time, so a scheduler that retries the
                                // same window does not create a second scan.
                                "schedule:" + schedule.getId() + ":" + schedule.getNextRunAt())
                                .getId());
                schedule.markRun(scanId);
                started.increment();
                log.info("schedule {} started scan {}", schedule.getName(), scanId);
            } catch (Exception exception) {
                // Deferred, never disabled. A target that was busy this minute is not a broken
                // schedule, and switching it off would silently stop the testing this exists to
                // guarantee.
                schedule.deferBy(DEFER_AFTER_REFUSAL);
                deferred.increment();
                log.warn(
                        "schedule {} deferred: {}",
                        schedule.getName(), exception.getMessage());
            }
        }
    }

    /**
     * The identity a scheduled scan runs as.
     *
     * <p>{@code machine=true} and {@code ENGINEER}: enough to run a scan, never enough to
     * change a policy or a target. The creator's id is carried so the audit row still names a
     * person - "the scheduler did it" is not an answer anybody accepts.
     */
    private Principal machinePrincipal(ScanSchedule schedule) {
        return new Principal(
                schedule.getCreatedBy(),
                "scheduler@agentshield.internal",
                schedule.getWorkspaceId(),
                Role.ENGINEER,
                true);
    }
}
