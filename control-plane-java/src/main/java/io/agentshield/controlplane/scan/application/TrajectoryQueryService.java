package io.agentshield.controlplane.scan.application;

import io.agentshield.controlplane.scan.domain.TrajectoryStep;
import io.agentshield.controlplane.scan.repository.RunRepository;
import io.agentshield.controlplane.scan.repository.ScenarioRepository;
import io.agentshield.controlplane.scan.repository.StepRepository;
import io.agentshield.controlplane.security.access.AccessGuard;
import io.agentshield.controlplane.security.domain.Permission;
import io.agentshield.controlplane.shared.error.NotFoundException;

import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Reads a stored trajectory back out.
 *
 * <p>A finding is a <em>sequence</em> - a document retrieved, a tool called with a value that
 * came out of it, an approval requested and never answered - and the evidence block cites step
 * indices into that sequence. Without a way to fetch the steps those indices point at, the
 * evidence is a set of numbers with nothing to number.
 *
 * <p>The steps returned here were redacted by the engine before they were ever transmitted, and
 * are stored that way: the columns are named {@code input_redacted} and {@code output_redacted}
 * because there is no unredacted version to reach for by mistake.
 */
@Service
public class TrajectoryQueryService {

    private final ScenarioRepository scenarios;
    private final RunRepository runs;
    private final StepRepository steps;
    private final AccessGuard access;

    public TrajectoryQueryService(
            ScenarioRepository scenarios,
            RunRepository runs,
            StepRepository steps,
            AccessGuard access) {
        this.scenarios = scenarios;
        this.runs = runs;
        this.steps = steps;
        this.access = access;
    }

    /**
     * Steps for the last attempt of a scenario, in order.
     *
     * <p>Ownership is checked on the scenario and again on the run. Checking only the scenario
     * would be enough today, and would stop being enough the moment anything else can create a
     * run - which is the kind of assumption that survives right up until it does not.
     */
    @Transactional(readOnly = true)
    public List<TrajectoryStep> forScenario(UUID scenarioId) {
        access.require(Permission.READ);

        var scenario = access.requireVisible(
                scenarios.findById(scenarioId)
                        .orElseThrow(() -> new NotFoundException("scenario", scenarioId)),
                "scenario",
                scenarioId);

        var run = runs.findFirstByScenarioIdOrderByAttemptDesc(scenario.getId())
                .orElse(null);
        if (run == null) {
            // A scenario that never produced a run is a scan that never reached the target, not
            // a scan with an empty trajectory. Empty is the honest answer; the caller renders it
            // as "no trajectory recorded" over an agent that did nothing.
            return List.of();
        }

        access.requireVisible(run, "attackRun", run.getId());
        return steps.findByAttackRunIdOrderBySequenceNumberAsc(run.getId());
    }
}
