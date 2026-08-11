package io.agentshield.controlplane.target.domain;

/**
 * The kind of system under test.
 *
 * <p>Each type knows which adapter drives it. Putting that here and not in a
 * {@code switch} inside a controller means adding a target type is one edit in one file, and
 * the compiler points at this enum instead of at whichever mapping someone forgot to update.
 *
 * <p>The names on the right are the engine's adapter ids, and they are a contract between two
 * languages that no compiler checks. {@code ASYNC_AGENT} pointed at {@code rest_generic} for a
 * whole stage: the async adapter existed, its tests passed, and every async target registered
 * through this API was driven by the generic one instead - output-only, so the approval window
 * that adapter exists to observe was invisible. Nothing failed, because a target that returns
 * an answer looks fine to a scanner that only reads answers.
 *
 * <p>{@code contracts/validate.py} now compares this enum against the engine's adapter
 * registry in both directions, so a rename on either side is a red build. Both directions,
 * because they fail differently: naming an adapter that does not exist throws at scan time,
 * and naming the wrong existing one fails silently, which is the case that happened.
 */
public enum TargetType {

    /** An agent behind an HTTP API. */
    REST_AGENT("rest_agentshield"),

    /** An MCP server, exercised by connecting as an MCP client. */
    MCP_SERVER("mcp"),

    /** A job-based agent: submit, poll, collect. */
    ASYNC_AGENT("async_agent"),

    /** One of the intentionally vulnerable targets shipped with AgentShield. */
    DEMO_TARGET("rest_agentshield");

    private final String defaultAdapter;

    TargetType(String defaultAdapter) {
        this.defaultAdapter = defaultAdapter;
    }

    /** Adapter used when the operator does not name one explicitly. */
    public String defaultAdapter() {
        return defaultAdapter;
    }
}
