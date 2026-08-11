package io.agentshield.controlplane.policy.domain;

import io.agentshield.controlplane.shared.domain.WorkspaceScoped;

import io.agentshield.controlplane.shared.domain.BaseEntity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.UUID;

/**
 * A versioned security policy document.
 *
 * <p>Immutable once written: changing a policy creates a new version instead of editing the
 * existing row. Findings reference {@link #getContentHash()}, and a policy that could change
 * underneath them would silently rewrite the meaning of every historical result - the
 * scan that "passed last week" would no longer be checkable.
 */
@Entity
@Table(name = "security_policy")
public class SecurityPolicy extends BaseEntity implements WorkspaceScoped {

    @Column(name = "workspace_id", nullable = false, updatable = false)
    private UUID workspaceId;

    @Column(name = "project_id", nullable = false, updatable = false)
    private UUID projectId;

    @Column(name = "name", nullable = false, updatable = false)
    private String name;

    @Column(name = "version", nullable = false, updatable = false)
    private int version;

    /** The YAML document, verbatim. */
    @Column(name = "content", nullable = false, updatable = false)
    private String content;

    @Column(name = "content_hash", nullable = false, updatable = false)
    private String contentHash;

    protected SecurityPolicy() {
    }

    public SecurityPolicy(UUID id, UUID workspaceId, UUID projectId, String name, int version, String content) {
        super(id);
        this.workspaceId = workspaceId;
        this.projectId = projectId;
        this.name = name;
        this.version = version;
        this.content = content;
        this.contentHash = hash(content);
    }

    /**
     * Hash of the document text.
     *
     * <p>Line endings are normalised first: a Windows checkout and a Linux CI runner must
     * produce the same hash for the same policy, or every cross-platform baseline comparison
     * reports a spurious mismatch.
     */
    public static String hash(String content) {
        String normalised = content.replace("\r\n", "\n").strip();
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(normalised.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest).substring(0, 16);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by the JVM specification", exception);
        }
    }

    public UUID getWorkspaceId() {
        return workspaceId;
    }

    public UUID getProjectId() {
        return projectId;
    }

    public String getName() {
        return name;
    }

    public int getVersion() {
        return version;
    }

    public String getContent() {
        return content;
    }

    public String getContentHash() {
        return contentHash;
    }
}
