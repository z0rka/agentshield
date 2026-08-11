package io.agentshield.controlplane.schedule.api;

import io.agentshield.controlplane.schedule.application.ScheduleService;
import io.agentshield.controlplane.schedule.domain.ScanSchedule;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Recurring scans. */
@RestController
@RequestMapping("/api")
public class ScheduleController {

    public record CreateScheduleRequest(
            @NotBlank String name,
            @NotNull UUID targetId,
            @NotNull UUID policyId,
            // Five minutes is the floor. Anything shorter is a load test of the target wearing
            // a schedule's clothes.
            @Min(5) @Max(43200) int intervalMinutes,
            List<String> suites,
            @Min(1) @Max(1000) Integer maxScenarios) {
    }

    public record EnabledRequest(boolean enabled) {
    }

    public record ScheduleResponse(
            UUID id,
            String name,
            UUID targetId,
            UUID policyId,
            int intervalMinutes,
            List<String> suites,
            int maxScenarios,
            boolean enabled,
            Instant nextRunAt,
            Instant lastRunAt,
            UUID lastScanId) {

        static ScheduleResponse of(ScanSchedule schedule) {
            return new ScheduleResponse(
                    schedule.getId(),
                    schedule.getName(),
                    schedule.getTargetId(),
                    schedule.getPolicyId(),
                    schedule.getIntervalMinutes(),
                    schedule.getSuites(),
                    schedule.getMaxScenarios(),
                    schedule.isEnabled(),
                    schedule.getNextRunAt(),
                    schedule.getLastRunAt(),
                    schedule.getLastScanId());
        }
    }

    private final ScheduleService schedules;

    public ScheduleController(ScheduleService schedules) {
        this.schedules = schedules;
    }

    @PostMapping("/projects/{projectId}/schedules")
    public ResponseEntity<ScheduleResponse> create(
            @PathVariable UUID projectId, @Valid @RequestBody CreateScheduleRequest request) {

        var schedule = schedules.create(
                projectId,
                request.targetId(),
                request.policyId(),
                request.name(),
                request.intervalMinutes(),
                request.suites(),
                request.maxScenarios() == null ? 50 : request.maxScenarios());
        return ResponseEntity.status(HttpStatus.CREATED).body(ScheduleResponse.of(schedule));
    }

    @GetMapping("/projects/{projectId}/schedules")
    public List<ScheduleResponse> list(@PathVariable UUID projectId) {
        return schedules.listForProject(projectId).stream().map(ScheduleResponse::of).toList();
    }

    /**
     * Pause or resume.
     *
     * <p>Separate from deletion on purpose. Pausing a schedule during an incident and resuming
     * it afterwards is routine, and making people delete and re-create it loses the record of
     * what has been running against that target.
     */
    @PostMapping("/schedules/{scheduleId}/enabled")
    public ScheduleResponse setEnabled(
            @PathVariable UUID scheduleId, @RequestBody EnabledRequest request) {
        return ScheduleResponse.of(schedules.setEnabled(scheduleId, request.enabled()));
    }

    @DeleteMapping("/schedules/{scheduleId}")
    public ResponseEntity<Void> delete(@PathVariable UUID scheduleId) {
        schedules.delete(scheduleId);
        return ResponseEntity.noContent().build();
    }
}
