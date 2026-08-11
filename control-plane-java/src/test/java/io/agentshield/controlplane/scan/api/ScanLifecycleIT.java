package io.agentshield.controlplane.scan.api;

import io.agentshield.controlplane.target.domain.TargetType;

import io.agentshield.controlplane.event.application.EngineEventHandler;
import io.agentshield.controlplane.event.domain.EventEnvelope;
import io.agentshield.controlplane.event.domain.EventTypes;
import io.agentshield.controlplane.event.repository.OutboxRepository;
import io.agentshield.controlplane.finding.domain.Finding;
import io.agentshield.controlplane.finding.repository.FindingRepository;
import io.agentshield.controlplane.policy.domain.SecurityPolicy;
import io.agentshield.controlplane.policy.repository.PolicyRepository;
import io.agentshield.controlplane.project.domain.Project;
import io.agentshield.controlplane.project.repository.ProjectRepository;
import io.agentshield.controlplane.scan.domain.ScanStatus;
import io.agentshield.controlplane.scan.repository.RunRepository;
import io.agentshield.controlplane.scan.repository.ScanRepository;
import io.agentshield.controlplane.scan.repository.ScenarioRepository;
import io.agentshield.controlplane.scan.repository.StepRepository;
import io.agentshield.controlplane.security.domain.Principal;
import io.agentshield.controlplane.security.domain.Role;
import io.agentshield.controlplane.target.domain.Target;
import io.agentshield.controlplane.target.repository.TargetRepository;
import io.agentshield.controlplane.workspace.domain.AppUser;
import io.agentshield.controlplane.workspace.domain.Workspace;
import io.agentshield.controlplane.workspace.domain.WorkspaceMember;
import io.agentshield.controlplane.workspace.repository.AppUserRepository;
import io.agentshield.controlplane.workspace.repository.WorkspaceMemberRepository;
import io.agentshield.controlplane.workspace.repository.WorkspaceRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Scan lifecycle against a real PostgreSQL.
 *
 * <p>Testcontainers over H2: the schema uses partial indexes, {@code FOR UPDATE SKIP
 * LOCKED} and {@code TIMESTAMPTZ}, none of which an in-memory database models faithfully. A
 * green suite against H2 would prove nothing about the queries that actually run.
 *
 * <p>Kafka is intentionally absent here. These tests assert what the *outbox* contains, which
 * is the control plane's real contract - the relay's delivery is covered separately.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class ScanLifecycleIT {

    @Container
    static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("agentshield")
                    .withUsername("agentshield")
                    .withPassword("agentshield");

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        // The relay would otherwise poll a broker that is not running.
        registry.add("spring.kafka.listener.auto-startup", () -> "false");
        registry.add("agentshield.outbox.poll-interval-ms", () -> "3600000");
    }

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired WorkspaceRepository workspaces;
    @Autowired AppUserRepository users;
    @Autowired WorkspaceMemberRepository members;
    @Autowired ProjectRepository projects;
    @Autowired TargetRepository targets;
    @Autowired PolicyRepository policies;
    @Autowired OutboxRepository outbox;
    @Autowired EngineEventHandler engineEvents;
    @Autowired ScenarioRepository scenarios;
    @Autowired RunRepository runs;
    @Autowired StepRepository steps;
    @Autowired ScanRepository scans;
    @Autowired FindingRepository findings;

    private UUID workspaceId;
    private UUID projectId;
    private UUID targetId;
    private UUID policyId;
    private Principal principal;

    @BeforeEach
    void seed() {
        findings.deleteAll();
        steps.deleteAll();
        runs.deleteAll();
        scenarios.deleteAll();
        outbox.deleteAll();
        workspaceId = UUID.randomUUID();
        workspaces.save(new Workspace(workspaceId, "Acme", "acme-" + workspaceId));

        var userId = UUID.randomUUID();
        users.save(new AppUser(userId, userId + "@company.test", "Engineer", "{noop}x"));
        members.save(new WorkspaceMember(workspaceId, userId, Role.ENGINEER));

        projectId = UUID.randomUUID();
        projects.save(new Project(projectId, workspaceId, "support-agent", ""));

        targetId = UUID.randomUUID();
        targets.save(new Target(
                targetId, workspaceId, projectId, "demo", TargetType.DEMO_TARGET,
                "rest_agentshield", "http://localhost:8090"));

        policyId = UUID.randomUUID();
        policies.save(new SecurityPolicy(
                policyId, workspaceId, projectId, "default", 1, "version: \"1\"\n"));

        principal = new Principal(
                userId, "engineer@company.test", workspaceId, Role.ENGINEER, false);
    }

    @Test
    @DisplayName("creating a scan writes the scan and its event in one transaction")
    void createWritesScanAndOutboxEntry() throws Exception {
        mvc.perform(post("/api/projects/{id}/scans", projectId)
                        .with(as(principal))
                        .contentType("application/json")
                        .content(json.writeValueAsString(Map.of(
                                "targetId", targetId,
                                "policyId", policyId,
                                "maxScenarios", 25))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.status").value("QUEUED"));

        var entries = outbox.findAll();
        assertThat(entries).hasSize(1);
        assertThat(entries.get(0).getEventType()).isEqualTo(EventTypes.SCAN_CREATED);
        assertThat(entries.get(0).getPublishedAt()).isNull();
    }

    @Test
    @DisplayName("the same idempotency key never starts a second scan")
    void repeatedIdempotencyKeyReturnsTheOriginal() throws Exception {
        String body = json.writeValueAsString(Map.of("targetId", targetId, "policyId", policyId));

        var first = mvc.perform(post("/api/projects/{id}/scans", projectId)
                        .with(as(principal))
                        .header("Idempotency-Key", "commit-abc123")
                        .contentType("application/json").content(body))
                .andExpect(status().isCreated())
                .andReturn();

        var second = mvc.perform(post("/api/projects/{id}/scans", projectId)
                        .with(as(principal))
                        .header("Idempotency-Key", "commit-abc123")
                        .contentType("application/json").content(body))
                .andExpect(status().isOk())
                .andReturn();

        String firstId = json.readTree(first.getResponse().getContentAsString()).get("id").asText();
        String secondId = json.readTree(second.getResponse().getContentAsString()).get("id").asText();
        assertThat(secondId).isEqualTo(firstId);

        // And crucially: one scan means one event, not two waves of traffic at the target.
        assertThat(outbox.findAll()).hasSize(1);
    }

    @Test
    @DisplayName("a second scan of the same target is refused while the first is in flight")
    void concurrentScansOfOneTargetAreRefused() throws Exception {
        mvc.perform(post("/api/projects/{id}/scans", projectId)
                        .with(as(principal))
                        .contentType("application/json")
                        .content(json.writeValueAsString(
                                Map.of("targetId", targetId, "policyId", policyId))))
                .andExpect(status().isCreated());

        // A distinct idempotency key, so this is a genuinely new request and not the
        // deduplicated replay that `idempotentScanCreation` covers.
        mvc.perform(post("/api/projects/{id}/scans", projectId)
                        .with(as(principal))
                        .header("Idempotency-Key", UUID.randomUUID().toString())
                        .contentType("application/json")
                        .content(json.writeValueAsString(
                                Map.of("targetId", targetId, "policyId", policyId))))
                .andExpect(status().isConflict());

        // Not merely load control. The indirect-injection suite plants documents in the
        // target, so a second concurrent scan retrieves the first one's poisoned article and
        // both trajectories stop being evidence of anything.
        // Counted by target, not globally: `seed` gives each test a fresh target but does
        // not clear the scan table, so a global count would pick up other tests' rows.
        assertThat(scans.countByTargetIdAndStatusIn(targetId, List.of(ScanStatus.QUEUED)))
                .isEqualTo(1);
    }

    @Test
    @DisplayName("a viewer cannot start a scan")
    void viewerCannotRunScans() throws Exception {
        var viewerId = UUID.randomUUID();
        users.save(new AppUser(viewerId, viewerId + "@company.test", "Viewer", "{noop}x"));
        members.save(new WorkspaceMember(workspaceId, viewerId, Role.VIEWER));
        var viewer = new Principal(
                viewerId, "viewer@company.test", workspaceId, Role.VIEWER, false);

        mvc.perform(post("/api/projects/{id}/scans", projectId)
                        .with(as(viewer))
                        .contentType("application/json")
                        .content(json.writeValueAsString(
                                Map.of("targetId", targetId, "policyId", policyId))))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("a duplicate attack event stores one redacted trajectory")
    void duplicateAttackEventIsPersistedOnce() throws Exception {
        var created = mvc.perform(post("/api/projects/{id}/scans", projectId)
                        .with(as(principal))
                        .contentType("application/json")
                        .content(json.writeValueAsString(
                                Map.of("targetId", targetId, "policyId", policyId))))
                .andExpect(status().isCreated())
                .andReturn();
        UUID scanId = UUID.fromString(
                json.readTree(created.getResponse().getContentAsString()).get("id").asText());

        var envelope = new EventEnvelope(
                UUID.randomUUID(),
                EventTypes.ATTACK_COMPLETED,
                EventTypes.CURRENT_VERSION,
                scanId.toString(),
                workspaceId,
                "trace-test",
                Instant.now(),
                null,
                attackPayload());

        engineEvents.applyLifecycle(envelope);
        engineEvents.applyLifecycle(envelope);

        assertThat(scenarios.findAll()).hasSize(1);
        assertThat(runs.findAll()).hasSize(1);
        assertThat(steps.findAll()).hasSize(1);
    }

    @Test
    @DisplayName("a finding's trajectory is readable, and it is the redacted one")
    void findingTrajectoryIsReadable() throws Exception {
        UUID scanId = startScan();
        storeTrajectory(scanId);

        var scenario = scenarios.findAll().get(0);
        var finding = findings.save(new Finding(
                UUID.randomUUID(),
                workspaceId,
                scanId,
                "AS-INJECTION-732",
                "INDIRECT_PROMPT_INJECTION",
                Finding.Severity.CRITICAL,
                "Instruction from untrusted content executed",
                "fp-injection-732"));
        finding.setScenarioId(scenario.getId());
        findings.save(finding);

        mvc.perform(get("/api/findings/{id}/trajectory", finding.getId()).with(as(principal)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].sequenceNumber").value(0))
                .andExpect(jsonPath("$[0].toolName").value("get_customer"))
                // The stored column is the redacted one. If this ever reads back the raw
                // canary, the engine stopped redacting before transmission and every report
                // built from these steps is leaking.
                .andExpect(jsonPath("$[0].inputRedacted").value("[REDACTED:canary]"));
    }

    @Test
    @DisplayName("another workspace's trajectory is absent, not forbidden")
    void crossWorkspaceTrajectoryLooksLikeItDoesNotExist() throws Exception {
        UUID scanId = startScan();
        storeTrajectory(scanId);

        var scenario = scenarios.findAll().get(0);
        var finding = findings.save(new Finding(
                UUID.randomUUID(),
                workspaceId,
                scanId,
                "AS-INJECTION-732",
                "INDIRECT_PROMPT_INJECTION",
                Finding.Severity.CRITICAL,
                "Instruction from untrusted content executed",
                "fp-injection-732"));
        finding.setScenarioId(scenario.getId());
        findings.save(finding);

        var otherWorkspace = UUID.randomUUID();
        workspaces.save(new Workspace(otherWorkspace, "Other", "other-" + otherWorkspace));
        var intruderId = UUID.randomUUID();
        users.save(new AppUser(intruderId, intruderId + "@other.test", "Intruder", "{noop}x"));
        members.save(new WorkspaceMember(otherWorkspace, intruderId, Role.OWNER));
        var intruder = new Principal(
                intruderId, "intruder@other.test", otherWorkspace, Role.OWNER, false);

        // 404, never 403. A 403 confirms the finding exists, which turns this endpoint into an
        // oracle for enumerating another tenant's findings.
        mvc.perform(get("/api/findings/{id}/trajectory", finding.getId()).with(as(intruder)))
                .andExpect(status().isNotFound());
    }

    /** One attack-completed payload: a scenario, one run, one already-redacted step. */
    private Map<String, Object> attackPayload() {
        return Map.of(
                "scenario", Map.of(
                        "key", "scenario-1",
                        "category", "INDIRECT_PROMPT_INJECTION",
                        "name", "poisoned document",
                        "templateId", "indirect-001",
                        "payload", Map.of("prompt", "show refund policy"),
                        "expectedPolicy", Map.of("forbidden_tools", List.of("send_email")),
                        "seed", 7,
                        "status", "SUCCESS"),
                "run", Map.of(
                        "attempt", 1,
                        "status", "SUCCESS",
                        "targetSessionId", "session-1",
                        "inputTokens", 12,
                        "outputTokens", 4,
                        "estimatedCostUsd", 0.001),
                "steps", List.of(Map.of(
                        "sequenceNumber", 0,
                        "stepType", "TOOL_RESULT",
                        "toolName", "get_customer",
                        "inputRedacted", "[REDACTED:canary]",
                        "outputRedacted", "{}",
                        "occurredAt", Instant.now().toString())));
    }

    /** Starts a scan the way the API does, and returns its id. */
    private UUID startScan() throws Exception {
        var created = mvc.perform(post("/api/projects/{id}/scans", projectId)
                        .with(as(principal))
                        .contentType("application/json")
                        .content(json.writeValueAsString(
                                Map.of("targetId", targetId, "policyId", policyId))))
                .andExpect(status().isCreated())
                .andReturn();
        return UUID.fromString(
                json.readTree(created.getResponse().getContentAsString()).get("id").asText());
    }

    /** Delivers one attack-completed event, which is how a trajectory comes to exist. */
    private void storeTrajectory(UUID scanId) {
        engineEvents.applyLifecycle(new EventEnvelope(
                UUID.randomUUID(),
                EventTypes.ATTACK_COMPLETED,
                EventTypes.CURRENT_VERSION,
                scanId.toString(),
                workspaceId,
                "trace-test",
                Instant.now(),
                null,
                attackPayload()));
    }

    @Test
    @DisplayName("a scan in another workspace is reported as absent, not as forbidden")
    void crossWorkspaceScanLooksLikeItDoesNotExist() throws Exception {
        var otherWorkspace = UUID.randomUUID();
        workspaces.save(new Workspace(otherWorkspace, "Other", "other-" + otherWorkspace));
        var intruderId = UUID.randomUUID();
        users.save(new AppUser(intruderId, intruderId + "@other.test", "Intruder", "{noop}x"));
        members.save(new WorkspaceMember(otherWorkspace, intruderId, Role.OWNER));

        var created = mvc.perform(post("/api/projects/{id}/scans", projectId)
                        .with(as(principal))
                        .contentType("application/json")
                        .content(json.writeValueAsString(
                                Map.of("targetId", targetId, "policyId", policyId))))
                .andReturn();
        String scanId = json.readTree(created.getResponse().getContentAsString()).get("id").asText();

        var intruder = new Principal(
                intruderId, "intruder@other.test", otherWorkspace, Role.OWNER, false);

        // 404, not 403: distinguishing the two would confirm the id exists.
        mvc.perform(get("/api/scans/{id}", scanId).with(as(intruder)))
                .andExpect(status().isNotFound());
    }

    private static RequestPostProcessor as(Principal principal) {
        return authentication(UsernamePasswordAuthenticationToken.authenticated(
                principal,
                null,
                List.of(new SimpleGrantedAuthority(principal.role().authority()))));
    }
}
