package io.agentshield.controlplane;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * The AgentShield control plane.
 *
 * <p>This service is the source of truth for everything durable: who may do what, which
 * targets exist, what a scan's status is, and which findings are open. The Python security
 * engine executes attacks and judges trajectories, but it never decides whether a scan is
 * running - it reports, and this service records.
 *
 * <p>That split matters when things fail. A Python worker can die mid-scan and be replaced;
 * the scan's state survives here, and the replacement resumes from what PostgreSQL says
 * already completed.
 */
@SpringBootApplication
@ConfigurationPropertiesScan
@EnableScheduling
public class AgentShieldApplication {

    public static void main(String[] args) {
        SpringApplication.run(AgentShieldApplication.class, args);
    }
}
