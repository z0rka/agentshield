package io.agentshield.controlplane.event.repository;

import io.agentshield.controlplane.event.domain.OutboxEntry;

import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Limit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface OutboxRepository extends JpaRepository<OutboxEntry, UUID> {

    @Query(value = """
            SELECT * FROM outbox_entry
            WHERE published_at IS NULL AND next_attempt_at <= now()
            ORDER BY created_at
            LIMIT :batchSize
            FOR UPDATE SKIP LOCKED
            """, nativeQuery = true)
    List<OutboxEntry> claimPending(@Param("batchSize") int batchSize);

    List<OutboxEntry> findByAggregateIdOrderByCreatedAt(String aggregateId, Limit limit);

    long countByPublishedAtIsNull();
}
