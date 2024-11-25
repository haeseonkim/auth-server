package com.abab.auth.repository;

import com.abab.auth.model.LogEntry;
import com.abab.auth.util.LogType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;

public interface LogRepository extends JpaRepository<LogEntry, Long> {
    @Query("SELECT l FROM LogEntry l WHERE l.userId = :userId" +
            " AND (:logType IS NULL OR l.logType = :logType)" +
            " AND (:startDate IS NULL OR l.timestamp >= :startDate)" +
            " AND (:endDate IS NULL OR l.timestamp <= :endDate)")
    Page<LogEntry> findLogsByUserIdAndLogTypeAndTimestampBetween(
            @Param("userId") Long userId,
            @Param("logType") LogType logType,
            @Param("startDate") Instant startDate,
            @Param("endDate") Instant endDate,
            Pageable pageable);
}
