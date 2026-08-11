package io.agentshield.controlplane.event.repository;

import io.agentshield.controlplane.event.domain.ProcessedEvent;

import java.time.Instant;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ProcessedEventRepository extends JpaRepository<ProcessedEvent, UUID> {

    @Modifying
    @Query(value = """
            INSERT INTO processed_event
                (event_id, event_type, consumer, workspace_id, processed_at)
            VALUES (:eventId, :eventType, :consumer, :workspaceId, now())
            ON CONFLICT (event_id) DO NOTHING
            """, nativeQuery = true)
    int claim(
            @Param("eventId") UUID eventId,
            @Param("eventType") String eventType,
            @Param("consumer") String consumer,
            @Param("workspaceId") UUID workspaceId);

    @Modifying
    @Query("DELETE FROM ProcessedEvent p WHERE p.processedAt < :before")
    int deleteProcessedBefore(@Param("before") Instant before);
}
