package io.agentshield.controlplane.target.domain;

import io.agentshield.controlplane.shared.domain.WorkspaceScoped;

import io.agentshield.controlplane.shared.domain.BaseEntity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/** A system under test. */
@Entity
@Table(name = "target")
public class Target extends BaseEntity implements WorkspaceScoped {


    @Column(name = "workspace_id", nullable = false, updatable = false)
    private UUID workspaceId;

    @Column(name = "project_id", nullable = false, updatable = false)
    private UUID projectId;

    @Column(name = "name", nullable = false)
    private String name;

    @Enumerated(EnumType.STRING)
    @Column(name = "type", nullable = false)
    private TargetType type;

    @Column(name = "adapter_type", nullable = false)
    private String adapterType;

    @Column(name = "base_url", nullable = false)
    private String baseUrl;

    @Column(name = "authentication_type", nullable = false)
    private String authenticationType = "NONE";

    /**
     * AES-GCM ciphertext of the adapter configuration, including any credentials.
     *
     * <p>Intentionally not exposed by a getter that returns it in a DTO-friendly form. The only
     * way out is {@link TargetService#decryptConfiguration}, so there is exactly one place to
     * audit for "where could a credential escape".
     */
    @Column(name = "configuration_encrypted")
    private byte[] configurationEncrypted;

    /** Hash of the non-secret configuration. Safe to log, print in reports and diff. */
    @Column(name = "configuration_hash", nullable = false)
    private String configurationHash = "";

    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    protected Target() {
    }

    public Target(
            UUID id,
            UUID workspaceId,
            UUID projectId,
            String name,
            TargetType type,
            String adapterType,
            String baseUrl) {
        super(id);
        this.workspaceId = workspaceId;
        this.projectId = projectId;
        this.name = name;
        this.type = type;
        this.adapterType = adapterType;
        this.baseUrl = baseUrl;
    }

    public void applyConfiguration(byte[] ciphertext, String configurationHash) {
        this.configurationEncrypted = ciphertext;
        this.configurationHash = configurationHash;
        this.updatedAt = Instant.now();
    }

    public byte[] configurationCiphertext() {
        return configurationEncrypted;
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

    public TargetType getType() {
        return type;
    }

    public String getAdapterType() {
        return adapterType;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public String getAuthenticationType() {
        return authenticationType;
    }

    public void setAuthenticationType(String authenticationType) {
        this.authenticationType = authenticationType;
    }

    public String getConfigurationHash() {
        return configurationHash;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
        this.updatedAt = Instant.now();
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    /** No credentials, no ciphertext, no configuration. Safe in a log line. */
    @Override
    public String toString() {
        return "Target[id=%s, name=%s, type=%s, configHash=%s]"
                .formatted(getId(), name, type, configurationHash);
    }
}
