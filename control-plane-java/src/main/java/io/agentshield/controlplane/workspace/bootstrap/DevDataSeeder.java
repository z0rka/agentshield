package io.agentshield.controlplane.workspace.bootstrap;

import io.agentshield.controlplane.project.domain.Project;
import io.agentshield.controlplane.project.repository.ProjectRepository;
import io.agentshield.controlplane.security.application.AuthenticationService;
import io.agentshield.controlplane.security.domain.Role;
import io.agentshield.controlplane.workspace.domain.AppUser;
import io.agentshield.controlplane.workspace.domain.CiToken;
import io.agentshield.controlplane.workspace.domain.Workspace;
import io.agentshield.controlplane.workspace.domain.WorkspaceMember;
import io.agentshield.controlplane.workspace.repository.AppUserRepository;
import io.agentshield.controlplane.workspace.repository.CiTokenRepository;
import io.agentshield.controlplane.workspace.repository.WorkspaceMemberRepository;
import io.agentshield.controlplane.workspace.repository.WorkspaceRepository;

import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Bootstraps a workspace so the system can be used at all.
 *
 * <p>There is deliberately no API for creating a workspace or a user: self-service signup for a
 * tool that generates adversarial traffic against production systems is not a feature anyone
 * wants shipped by default. Provisioning belongs to an operator, and in a real deployment that
 * means SSO plus an admin path.
 *
 * <p>That leaves a chicken-and-egg problem for local work and for the smoke test: without a
 * workspace, a user and a role, nothing downstream can be exercised. This seeder solves exactly
 * that, and is fenced in three ways so it cannot leak into a real deployment:
 *
 * <ul>
 *   <li>it only exists under the {@code local} and {@code demo} profiles;
 *   <li>it only runs when the workspace table is empty, so a restart never overwrites real data;
 *   <li>it logs a loud warning naming the well-known credentials it created.
 * </ul>
 *
 * <p>Identifiers are derived from fixed names rather than random, so the smoke test and the demo
 * script can reference them without scraping log output.
 */
@Component
@Profile({"local", "demo"})
public class DevDataSeeder implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DevDataSeeder.class);

    /** Well-known development credentials. Safe only because the profile is fenced. */
    public static final String OWNER_EMAIL = "owner@company.test";
    public static final String ENGINEER_EMAIL = "engineer@company.test";
    public static final String VIEWER_EMAIL = "viewer@company.test";
    public static final String DEV_PASSWORD = "agentshield-dev";
    public static final String DEV_CI_TOKEN = "agentshield-dev-ci-token";
    public static final String PROJECT_NAME = "support-agent";

    public static final UUID WORKSPACE_ID = deterministic("workspace");
    public static final UUID PROJECT_ID = deterministic("project");

    private final WorkspaceRepository workspaces;
    private final AppUserRepository users;
    private final WorkspaceMemberRepository members;
    private final ProjectRepository projects;
    private final CiTokenRepository ciTokens;
    private final PasswordEncoder passwordEncoder;

    public DevDataSeeder(
            WorkspaceRepository workspaces,
            AppUserRepository users,
            WorkspaceMemberRepository members,
            ProjectRepository projects,
            CiTokenRepository ciTokens,
            PasswordEncoder passwordEncoder) {
        this.workspaces = workspaces;
        this.users = users;
        this.members = members;
        this.projects = projects;
        this.ciTokens = ciTokens;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        if (workspaces.count() > 0) {
            log.info("workspace data already present; dev seeding skipped");
            return;
        }

        workspaces.save(new Workspace(WORKSPACE_ID, "Development", "development"));

        var owner = seedUser(OWNER_EMAIL, "Dev Owner", Role.OWNER);
        seedUser(ENGINEER_EMAIL, "Dev Engineer", Role.ENGINEER);
        seedUser(VIEWER_EMAIL, "Dev Viewer", Role.VIEWER);

        projects.save(new Project(PROJECT_ID, WORKSPACE_ID, PROJECT_NAME, "Local demo project"));

        ciTokens.save(new CiToken(
                deterministic("ci-token"),
                WORKSPACE_ID,
                PROJECT_ID,
                "local-ci",
                AuthenticationService.hash(DEV_CI_TOKEN),
                owner.getId(),
                null));

        log.warn(
                """

                ════════════════════════════════════════════════════════════════════
                 DEVELOPMENT DATA SEEDED - well-known credentials are now active.
                 This runs only under the 'local' and 'demo' profiles. Never enable
                 either in a deployment that can reach a real target.

                   workspace : {}
                   project   : {} ({})
                   users     : {} / {} / {}
                   password  : {}
                   CI token  : {}
                ════════════════════════════════════════════════════════════════════
                """,
                WORKSPACE_ID,
                PROJECT_NAME,
                PROJECT_ID,
                OWNER_EMAIL,
                ENGINEER_EMAIL,
                VIEWER_EMAIL,
                DEV_PASSWORD,
                DEV_CI_TOKEN);
    }

    private AppUser seedUser(String email, String displayName, Role role) {
        var user = users.save(new AppUser(
                deterministic("user:" + email),
                email,
                displayName,
                passwordEncoder.encode(DEV_PASSWORD)));
        members.save(new WorkspaceMember(WORKSPACE_ID, user.getId(), role));
        return user;
    }

    /**
     * A UUID derived from a fixed name.
     *
     * <p>Stable across machines and restarts, which is what lets the smoke test address these
     * rows directly without parsing them out of a log line.
     */
    private static UUID deterministic(String name) {
        return UUID.nameUUIDFromBytes(("agentshield:dev:" + name).getBytes(StandardCharsets.UTF_8));
    }
}
