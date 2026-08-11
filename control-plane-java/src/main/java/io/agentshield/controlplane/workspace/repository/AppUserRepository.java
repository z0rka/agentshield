package io.agentshield.controlplane.workspace.repository;

import io.agentshield.controlplane.workspace.domain.AppUser;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepository extends JpaRepository<AppUser, UUID> {

    Optional<AppUser> findByEmailIgnoreCase(String email);
}
