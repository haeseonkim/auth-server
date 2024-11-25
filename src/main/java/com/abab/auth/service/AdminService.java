package com.abab.auth.service;

import com.abab.auth.model.LogEntry;
import com.abab.auth.model.LogEntryDTO;
import com.abab.auth.repository.LogRepository;
import com.abab.auth.util.LogType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class AdminService {
    private final LogRepository logRepository;

    public Page<LogEntryDTO> getUserLogs(Long userId, LogType logType, Instant startDate, Instant endDate, int page, int size) {
        Pageable pageable = PageRequest.of(page, size);
        Page<LogEntry> logPage = logRepository.findLogsByUserIdAndLogTypeAndTimestampBetween(userId, logType, startDate, endDate, pageable);

        log.info("Log entries size: {}", logPage.getTotalElements());  // 로그 개수 출력
        logPage.getContent().forEach(logEntry -> log.info("Log entry: {}", logEntry));

        // LogEntry를 LogEntryDTO로 변환
        List<LogEntryDTO> logEntryDTOs = logPage.getContent().stream()
                .map(logEntry -> new LogEntryDTO(
                        logEntry.getUserId(),
                        logEntry.getLogType(),
                        logEntry.getTimestamp(),
                        logEntry.getMessage()
                ))
                .toList();

        return new PageImpl<>(logEntryDTOs, pageable, logPage.getTotalElements());
    }
}