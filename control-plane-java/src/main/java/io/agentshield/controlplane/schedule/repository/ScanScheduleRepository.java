package io.agentshield.controlplane.schedule.repository;

import io.agentshield.controlplane.schedule.domain.ScanSchedule;

import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ScanScheduleRepository extends JpaRepository<ScanSchedule, UUID> {

    List<ScanSchedule> findByProjectIdOrderByNameAsc(UUID projectId);

    /**
     * Schedules that are due, claimed for this poller.
     *
     * <p>{@code FOR UPDATE SKIP LOCKED}, the same pattern as the outbox and for the same
     * reason: two replicas poll the same table, and without the lock both would see the same
     * due row and start the same scan twice. Skipping locked rows means the second replica
     * takes the next one and does not wait behind the first.
     */
    @Query(value = """
            SELECT * FROM scan_schedule
            WHERE enabled AND next_run_at <= now()
            ORDER BY next_run_at
            LIMIT :batchSize
            FOR UPDATE SKIP LOCKED
            """, nativeQuery = true)
    List<ScanSchedule> claimDue(@Param("batchSize") int batchSize);
}
