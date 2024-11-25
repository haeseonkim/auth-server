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
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
@Slf4j
public class AdminService {
    private final LogRepository logRepository;
    private final ConcurrentHashMap<Long, Instant> userTokenExpiryMap = new ConcurrentHashMap<>();

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

    public void expireUserTokens(Long userId) {
        // 현재 시점을 만료 시점으로 설정
        Instant currentExpiryTime = Instant.now();
        userTokenExpiryMap.put(userId, currentExpiryTime);
        log.info("User {} tokens expired at {}", userId, currentExpiryTime);

        // 로그 기록 저장
        saveLog(userId, "All tokens for user " + userId + " have been expired by admin.");
    }

    public boolean isTokenValid(Long userId, Instant tokenIssueTime) {
        // 만료 시점 이후에 발급된 토큰만 유효
        Instant expiryTime = userTokenExpiryMap.get(userId);
        return expiryTime == null || tokenIssueTime.isAfter(expiryTime);
    }

    private void saveLog(Long userId, String message) {
        LogEntry logEntry = LogEntry.builder()
                .userId(userId)
                .logType(LogType.TOKEN_EXPIRATION)
                .timestamp(Instant.now())
                .message(message)
                .build();
        logRepository.save(logEntry);
    }
}