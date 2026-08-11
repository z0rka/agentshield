package io.agentshield.controlplane.shared.web;

import java.time.Instant;
import java.util.List;

/**
 * The single error shape every failing request returns.
 *
 * <p>One shape for every failure so a client can parse errors without branching on endpoint.
 * {@code code} is the stable contract; {@code message} is for humans and may be reworded.
 */
public record ApiError(
        String code,
        String message,
        List<String> details,
        String path,
        Instant timestamp) {

    public static ApiError of(String code, String message, String path) {
        return new ApiError(code, message, List.of(), path, Instant.now());
    }

    public static ApiError of(String code, String message, List<String> details, String path) {
        return new ApiError(code, message, List.copyOf(details), path, Instant.now());
    }
}
