package io.agentshield.controlplane.workspace.repository;

import io.agentshield.controlplane.workspace.domain.WorkspaceMember;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface WorkspaceMemberRepository
        extends JpaRepository<WorkspaceMember, WorkspaceMember.Id> {

    List<WorkspaceMember> findByIdUserId(UUID userId);

    Optional<WorkspaceMember> findByIdWorkspaceIdAndIdUserId(UUID workspaceId, UUID userId);

    List<WorkspaceMember> findByIdWorkspaceId(UUID workspaceId);

    @Query("""
            SELECT m FROM WorkspaceMember m
            WHERE m.id.userId = :userId
            ORDER BY m.createdAt ASC
            """)
    List<WorkspaceMember> findMembershipsInOrder(@Param("userId") UUID userId);
}
