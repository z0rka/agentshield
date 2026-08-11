package io.agentshield.controlplane.event.application;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.agentshield.controlplane.event.domain.EventEnvelope;
import io.agentshield.controlplane.event.domain.EventTypes;
import io.agentshield.controlplane.finding.repository.FindingRepository;
import io.agentshield.controlplane.policy.domain.SecurityPolicy;
import io.agentshield.controlplane.policy.repository.PolicyRepository;
import io.agentshield.controlplane.project.domain.Project;
import io.agentshield.controlplane.project.repository.ProjectRepository;
import io.agentshield.controlplane.scan.domain.Scan;
import io.agentshield.controlplane.scan.repository.ScanRepository;
import io.agentshield.controlplane.scan.repository.ScenarioRepository;
import io.agentshield.controlplane.target.domain.Target;
import io.agentshield.controlplane.target.domain.TargetType;
import io.agentshield.controlplane.target.repository.TargetRepository;
import io.agentshield.controlplane.workspace.domain.AppUser;
import io.agentshield.controlplane.workspace.domain.Workspace;
import io.agentshield.controlplane.workspace.repository.AppUserRepository;
import io.agentshield.controlplane.workspace.repository.WorkspaceRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * What happens when the queue misbehaves.
 *
 * <p>Delivery is at-least-once on purpose, so "the same event twice" is not a fault to be
 * prevented - it is the normal case the consumers are built for. The architecture claims two
 * independent defences, and they catch different things:
 *
 * <ul>
 *   <li>{@code processed_event} claims each {@code eventId} by primary key, which stops a
 *       redelivery of the <em>same</em> message;
 *   <li>findings deduplicate on {@code (scan_id, fingerprint)}, which stops the same defect
 *       arriving under a <em>new</em> event id after the engine retried a scenario.
 * </ul>
 *
 * <p>The second is the one an event-id guard cannot do, and it is the one that fires in
 * practice, because a worker that dies after publishing and before committing its offset
 * republishes with fresh ids. Tests that only redeliver an identical envelope prove the easy
 * half.
 *
 * <p>Against a real PostgreSQL, because the claim is a primary-key insert race and the finding
 * dedup is a unique constraint. Neither is modelled honestly by an in-memory database.
 */
@SpringBootTest
@Testcontainers
@DisplayName("event replay")
class EventReplayChaosIT {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine");

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.kafka.listener.auto-startup", () -> "false");
    }

    @Autowired EngineEventHandler engineEvents;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;
    @Autowired ScenarioRepository scenarios;
    @Autowired WorkspaceRepository workspaces;
    @Autowired AppUserRepository users;
    @Autowired ProjectRepository projects;
    @Autowired TargetRepository targets;
    @Autowired PolicyRepository policies;
    @Autowired ObjectMapper json;

    private UUID workspaceId;
    private UUID scanId;

    @BeforeEach
    void seed() {
        findings.deleteAll();
        scenarios.deleteAll();
        scans.deleteAll();

        var workspace = workspaces.save(new Workspace(UUID.randomUUID(), "chaos", "chaos-" + UUID.randomUUID()));
        workspaceId = workspace.getId();
        var project = projects.save(new Project(UUID.randomUUID(), workspaceId, "p", "p"));
        var target = targets.save(new Target(
                UUID.randomUUID(), workspaceId, project.getId(), "t",
                TargetType.REST_AGENT, "https://example.test", "{}"));
        var policy = policies.save(new SecurityPolicy(
                UUID.randomUUID(), workspaceId, project.getId(), "pol", 1, "version: \"1\""));
        // A real user row: `scan.requested_by` is a foreign key, and every scan in this system
        // is attributable to whoever asked for it.
        var userId = UUID.randomUUID();
        var user = users.save(new AppUser(
                userId, userId + "@company.test", "Chaos", "{noop}x"));
        var scan = new Scan(
                UUID.randomUUID(),
                workspaceId,
                project.getId(),
                target.getId(),
                policy.getId(),
                user.getId(),
                "chaos-" + UUID.randomUUID(),
                "chaos");
        // A new Scan is CREATED; the API queues it before any engine event arrives. Starting
        // the fixture in the wrong state makes every lifecycle transition illegal and the
        // resulting failures look like idempotency bugs, which is how this test first read.
        scan.tryTransitionTo(io.agentshield.controlplane.scan.domain.ScanStatus.QUEUED);
        scanId = scans.save(scan).getId();
    }

    // -----------------------------------------------------------------------------
    // the defence an event-id guard cannot provide
    // -----------------------------------------------------------------------------

    @Test
    @DisplayName("the same defect under a new event id is one finding, not two")
    void engineRetryDoesNotDuplicateAFinding() {
        engineEvents.applyFinding(finding(UUID.randomUUID(), "fp-abc123", "AS-LEAK-078"));
        engineEvents.applyFinding(finding(UUID.randomUUID(), "fp-abc123", "AS-LEAK-078"));

        // Distinct event ids, so `processed_event` claims both. Only the fingerprint check
        // stands between a retried scenario and a report that double-counts every finding.
        assertThat(findings.findAll()).hasSize(1);
    }

    @Test
    @DisplayName("a repeated defect is counted, not silently dropped")
    void repeatedDeliveryRecordsAnOccurrence() {
        engineEvents.applyFinding(finding(UUID.randomUUID(), "fp-count", "AS-LEAK-078"));
        engineEvents.applyFinding(finding(UUID.randomUUID(), "fp-count", "AS-LEAK-078"));

        // Deduplicated is not the same as discarded: how often a defect reproduced is evidence
        // about how reliably it triggers, and the report says so.
        assertThat(findings.findAll().getFirst().getOccurrences()).isGreaterThan(1);
    }

    @Test
    @DisplayName("different defects on one scan stay separate")
    void distinctFingerprintsAreNotCollapsed() {
        engineEvents.applyFinding(finding(UUID.randomUUID(), "fp-one", "AS-LEAK-078"));
        engineEvents.applyFinding(finding(UUID.randomUUID(), "fp-two", "AS-TENANT-545"));

        // The failure mode opposite to duplication, and the more dangerous one: a dedup key
        // that is too coarse hides real findings behind one that was already reported.
        assertThat(findings.findAll()).hasSize(2);
    }

    // -----------------------------------------------------------------------------
    // replaying the whole stream
    // -----------------------------------------------------------------------------

    @Test
    @DisplayName("replaying every event leaves the same state")
    void wholeStreamReplayedIsIdempotent() {
        List<EventEnvelope> stream = List.of(
                lifecycle(EventTypes.SCAN_STARTED, Map.of("status", "RUNNING")),
                finding(UUID.randomUUID(), "fp-alpha", "AS-LEAK-078"),
                finding(UUID.randomUUID(), "fp-beta", "AS-AGENCY-097"),
                lifecycle(EventTypes.SCAN_COMPLETED, Map.of("status", "COMPLETED")));

        stream.forEach(this::dispatch);
        var afterFirstPass = scans.findById(scanId).orElseThrow().getStatus();

        stream.forEach(this::dispatch);

        assertThat(findings.findAll()).hasSize(2);
        assertThat(scans.findById(scanId).orElseThrow().getStatus()).isEqualTo(afterFirstPass);
    }

    @Test
    @DisplayName("a shuffled replay still converges on the same state")
    void outOfOrderReplayConverges() {
        List<EventEnvelope> stream = new ArrayList<>(List.of(
                lifecycle(EventTypes.SCAN_STARTED, Map.of("status", "RUNNING")),
                finding(UUID.randomUUID(), "fp-alpha", "AS-LEAK-078"),
                finding(UUID.randomUUID(), "fp-beta", "AS-AGENCY-097"),
                lifecycle(EventTypes.SCAN_COMPLETED, Map.of("status", "COMPLETED"))));

        stream.forEach(this::dispatch);
        // Kafka orders within a partition, not across them, and a redelivery after a rebalance
        // need not arrive in the original order. Convergence must not depend on luck.
        Collections.shuffle(stream, new java.util.Random(7));
        stream.forEach(this::dispatch);

        assertThat(findings.findAll()).hasSize(2);
        assertThat(scans.findById(scanId).orElseThrow().getStatus().isTerminal()).isTrue();
    }

    @Test
    @DisplayName("a late event cannot reopen a completed scan")
    void lateEventCannotReopenCompletedScan() {
        // Driven through the real path first: QUEUED -> RUNNING -> COMPLETED. Jumping straight
        // to COMPLETED is not a legal transition and would test nothing.
        dispatch(lifecycle(EventTypes.SCAN_STARTED, Map.of("status", "RUNNING")));
        dispatch(lifecycle(EventTypes.SCAN_COMPLETED, Map.of("status", "COMPLETED")));
        assertThat(scans.findById(scanId).orElseThrow().getStatus().isTerminal()).isTrue();

        dispatch(lifecycle(EventTypes.SCAN_STARTED, Map.of("status", "RUNNING")));

        // A scan that flips back to RUNNING after finishing is a scan whose reported status
        // nobody can act on, and the CI gate reads exactly this field.
        assertThat(scans.findById(scanId).orElseThrow().getStatus().isTerminal()).isTrue();
    }

    // -----------------------------------------------------------------------------
    // helpers
    // -----------------------------------------------------------------------------

    private void dispatch(EventEnvelope envelope) {
        if (EventTypes.FINDING_CREATED.equals(envelope.eventType())) {
            engineEvents.applyFinding(envelope);
        } else {
            engineEvents.applyLifecycle(envelope);
        }
    }

    private EventEnvelope finding(UUID eventId, String fingerprint, String code) {
        return new EventEnvelope(
                eventId,
                EventTypes.FINDING_CREATED,
                EventTypes.CURRENT_VERSION,
                scanId.toString(),
                workspaceId,
                "chaos",
                Instant.now(),
                null,
                Map.of(
                        "fingerprint", fingerprint,
                        "code", code,
                        "category", "DATA_LEAKAGE",
                        "severity", "CRITICAL",
                        "title", "canary reached an outbound tool",
                        "detectedBy", "SensitiveDataLeakEvaluator"));
    }

    private EventEnvelope lifecycle(String type, Map<String, Object> payload) {
        return new EventEnvelope(
                UUID.randomUUID(),
                type,
                EventTypes.CURRENT_VERSION,
                scanId.toString(),
                workspaceId,
                "chaos",
                Instant.now(),
                null,
                payload);
    }
}
