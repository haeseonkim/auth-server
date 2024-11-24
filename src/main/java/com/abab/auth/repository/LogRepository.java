package com.abab.auth.repository;

import com.abab.auth.model.LogEntry;
import com.abab.auth.util.LogType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;

public interface LogRepository extends JpaRepository<LogEntry, Long> {
    Page<LogEntry> findLogsByUserIdAndLogTypeAndTimestampBetween(Long userId, LogType logType, Instant startDate, Instant endDate, Pageable pageable);
}
