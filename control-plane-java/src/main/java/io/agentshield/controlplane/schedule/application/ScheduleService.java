package io.agentshield.controlplane.schedule.application;

import io.agentshield.controlplane.policy.application.PolicyService;
import io.agentshield.controlplane.schedule.domain.ScanSchedule;
import io.agentshield.controlplane.schedule.repository.ScanScheduleRepository;
import io.agentshield.controlplane.security.access.AccessGuard;
import io.agentshield.controlplane.security.domain.Permission;
import io.agentshield.controlplane.shared.error.InvalidRequestException;
import io.agentshield.controlplane.shared.error.NotFoundException;
import io.agentshield.controlplane.target.application.TargetService;

import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Managing recurring scans. */
@Service
public class ScheduleService {

    private final ScanScheduleRepository schedules;
    private final TargetService targets;
    private final PolicyService policies;
    private final AccessGuard access;

    public ScheduleService(
            ScanScheduleRepository schedules,
            TargetService targets,
            PolicyService policies,
            AccessGuard access) {
        this.schedules = schedules;
        this.targets = targets;
        this.policies = policies;
        this.access = access;
    }

    /**
     * Create a schedule.
     *
     * <p>Requires {@code RUN_SCAN}, never {@code WRITE}. Creating a schedule is creating scans -
     * every scan it will ever start, without anyone approving them one at a time - so it cannot
     * sit behind a lesser permission than starting one by hand.
     */
    @Transactional
    public ScanSchedule create(
            UUID projectId,
            UUID targetId,
            UUID policyId,
            String name,
            int intervalMinutes,
            List<String> suites,
            int maxScenarios) {

        var principal = access.require(Permission.RUN_SCAN);

        var target = targets.require(targetId);
        var policy = policies.require(policyId);
        if (!target.getProjectId().equals(projectId) || !policy.getProjectId().equals(projectId)) {
            throw new InvalidRequestException("target and policy must belong to the named project");
        }

        return schedules.save(new ScanSchedule(
                UUID.randomUUID(),
                principal.workspaceId(),
                projectId,
                targetId,
                policyId,
                name,
                intervalMinutes,
                suites,
                maxScenarios,
                principal.userId()));
    }

    @Transactional(readOnly = true)
    public List<ScanSchedule> listForProject(UUID projectId) {
        access.require(Permission.READ);
        return access.requireAllVisible(
                schedules.findByProjectIdOrderByNameAsc(projectId), "schedule");
    }

    @Transactional
    public ScanSchedule setEnabled(UUID scheduleId, boolean enabled) {
        access.require(Permission.RUN_SCAN);
        var schedule = require(scheduleId);
        schedule.setEnabled(enabled);
        return schedule;
    }

    @Transactional
    public void delete(UUID scheduleId) {
        access.require(Permission.ADMINISTER);
        schedules.delete(require(scheduleId));
    }

    private ScanSchedule require(UUID scheduleId) {
        return access.requireVisible(
                schedules.findById(scheduleId)
                        .orElseThrow(() -> new NotFoundException("schedule", scheduleId)),
                "schedule",
                scheduleId);
    }
}
