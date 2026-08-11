package io.agentshield.controlplane.workspace.repository;

import io.agentshield.controlplane.workspace.domain.CiToken;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CiTokenRepository extends JpaRepository<CiToken, UUID> {

    Optional<CiToken> findByTokenHash(String tokenHash);

    List<CiToken> findByWorkspaceId(UUID workspaceId);
}
