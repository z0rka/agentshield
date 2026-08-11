package io.agentshield.controlplane.target.application;

import io.agentshield.controlplane.target.domain.TargetType;

import io.agentshield.controlplane.security.access.AccessGuard;
import io.agentshield.controlplane.security.domain.Permission;
import io.agentshield.controlplane.shared.error.ConflictException;
import io.agentshield.controlplane.shared.error.InvalidRequestException;
import io.agentshield.controlplane.shared.error.NotFoundException;
import io.agentshield.controlplane.target.domain.Target;
import io.agentshield.controlplane.target.repository.TargetRepository;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Target lifecycle, including the single sanctioned path to a decrypted configuration. */
@Service
public class TargetService {

    /**
     * Configuration keys treated as secret.
     *
     * <p>Excluded from the configuration hash so that rotating a credential does not
     * invalidate a regression baseline, and stripped from every response and log line.
     */
    static final Set<String> SECRET_KEYS =
            Set.of("api_key", "token", "password", "secret", "authorization", "headers");

    private final TargetRepository targets;
    private final CredentialCipher cipher;
    private final ObjectMapper objectMapper;
    private final AccessGuard access;
    private final SsrfGuard ssrf;

    public TargetService(
            TargetRepository targets,
            CredentialCipher cipher,
            ObjectMapper objectMapper,
            AccessGuard access,
            SsrfGuard ssrf) {
        this.targets = targets;
        this.cipher = cipher;
        this.objectMapper = objectMapper;
        this.access = access;
        this.ssrf = ssrf;
    }

    @Transactional
    public Target create(
            UUID projectId,
            String name,
            TargetType type,
            String adapterType,
            String baseUrl,
            Map<String, Object> configuration) {

        var principal = access.require(Permission.WRITE);

        if (targets.existsByProjectIdAndName(projectId, name)) {
            throw new ConflictException("a target named '" + name + "' already exists");
        }
        requireHttpUrl(baseUrl);

        var target = new Target(
                UUID.randomUUID(),
                principal.workspaceId(),
                projectId,
                name,
                type,
                adapterType,
                baseUrl);
        applyConfiguration(target, configuration);
        return targets.save(target);
    }

    @Transactional
    public void applyConfiguration(Target target, Map<String, Object> configuration) {
        try {
            String json = objectMapper.writeValueAsString(configuration == null ? Map.of() : configuration);
            target.applyConfiguration(cipher.encrypt(json), configurationHash(configuration));
        } catch (JsonProcessingException exception) {
            throw new InvalidRequestException("target configuration is not serialisable");
        }
    }

    @Transactional(readOnly = true)
    public Target require(UUID targetId) {
        access.require(Permission.READ);
        return access.requireVisible(
                targets.findById(targetId)
                        .orElseThrow(() -> new NotFoundException("target", targetId)),
                "target",
                targetId);
    }

    @Transactional(readOnly = true)
    public List<Target> listForProject(UUID projectId) {
        access.require(Permission.READ);
        return targets.findByProjectIdOrderByCreatedAtDesc(projectId);
    }

    /**
     * Decrypts the adapter configuration for dispatch to the engine.
     *
     * <p>The only caller should be the scan dispatcher. The result contains live credentials
     * and must never reach a response body, a log, a span attribute or a report.
     */
    @Transactional(readOnly = true)
    public Map<String, Object> decryptConfiguration(Target target) {
        String json = cipher.decrypt(target.configurationCiphertext());
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            return objectMapper.readValue(json, new com.fasterxml.jackson.core.type.TypeReference<>() {
            });
        } catch (JsonProcessingException exception) {
            throw new InvalidRequestException("stored target configuration could not be parsed");
        }
    }

    /** Complete adapter configuration for the engine's private channel only. */
    @Transactional(readOnly = true)
    public Map<String, Object> engineConfiguration(Target target) {
        var configuration = new HashMap<>(decryptConfiguration(target));
        // Stored entity fields are authoritative. A user-supplied configuration cannot point
        // the worker at a different host or swap the adapter after validation.
        configuration.put("base_url", target.getBaseUrl());
        configuration.put("adapter_type", target.getAdapterType());
        configuration.put("type", target.getType().name());
        return Map.copyOf(configuration);
    }

    /** Configuration with every secret replaced, for responses and logs. */
    public Map<String, Object> redact(Map<String, Object> configuration) {
        var redacted = new TreeMap<String, Object>();
        configuration.forEach((key, value) ->
                redacted.put(key, SECRET_KEYS.contains(key.toLowerCase()) ? "***" : value));
        return redacted;
    }

    /**
     * Stable hash of the non-secret configuration.
     *
     * <p>Recorded on every scan so a finding can state exactly which target shape produced it.
     */
    String configurationHash(Map<String, Object> configuration) {
        if (configuration == null || configuration.isEmpty()) {
            return "";
        }
        var sorted = new TreeMap<String, Object>();
        configuration.forEach((key, value) -> {
            if (!SECRET_KEYS.contains(key.toLowerCase())) {
                sorted.put(key, value);
            }
        });
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(objectMapper.writeValueAsString(sorted).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest).substring(0, 16);
        } catch (NoSuchAlgorithmException | JsonProcessingException exception) {
            throw new IllegalStateException("failed to hash target configuration", exception);
        }
    }

    /** Delegates to {@link SsrfGuard}, which resolves the host and refuses internal addresses. */
    private void requireHttpUrl(String baseUrl) {
        ssrf.check(baseUrl);
    }
}
