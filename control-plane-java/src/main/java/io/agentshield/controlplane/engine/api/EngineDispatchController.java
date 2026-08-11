package io.agentshield.controlplane.engine.api;

import io.agentshield.controlplane.engine.application.EngineDispatchService;
import io.agentshield.controlplane.engine.domain.EngineScanDispatch;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/** Private pull channel for credentials and policy text that must never enter Kafka. */
@RestController
@RequestMapping("/internal/engine")
public class EngineDispatchController {

    private final EngineDispatchService dispatches;
    private final byte[] expectedToken;

    public EngineDispatchController(
            EngineDispatchService dispatches,
            @Value("${agentshield.internal-token}") String expectedToken) {
        this.dispatches = dispatches;
        this.expectedToken = expectedToken.getBytes(StandardCharsets.UTF_8);
    }

    @GetMapping("/scans/{scanId}")
    public EngineScanDispatch dispatch(
            @PathVariable UUID scanId,
            @RequestHeader(value = "X-AgentShield-Internal-Token", required = false) String token) {
        authenticate(token);
        return dispatches.load(scanId);
    }

    private void authenticate(String token) {
        byte[] presented = token == null
                ? new byte[0]
                : token.getBytes(StandardCharsets.UTF_8);
        if (expectedToken.length == 0 || !MessageDigest.isEqual(expectedToken, presented)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }
    }
}
