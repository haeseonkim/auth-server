package com.abab.auth.service;

import com.abab.auth.model.LogEntry;
import com.abab.auth.model.LogEntryDTO;
import com.abab.auth.model.User;
import com.abab.auth.model.UserWebDTO;
import com.abab.auth.repository.LogRepository;
import com.abab.auth.repository.UserRepository;
import com.abab.auth.util.JwtTokenUtil;
import com.abab.auth.util.LogType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class AdminServiceTest {
    @Mock
    private LogRepository logRepository;

    @InjectMocks
    private AdminService adminService;

    @Nested
    @DisplayName("GetUserLogsTests")
    class GetUserLogsTests {

        @Test
        @WithMockUser(roles = "ADMIN")
        @DisplayName("관리자 권한으로 로그 조회 성공")
        void testGetUserLogsSuccessWithAdminRole() {
            // Given
            Long userId = 1L;
            LogType logType = LogType.LOGIN_SUCCESS;
            Instant startDate = Instant.now().minusSeconds(3600);
            Instant endDate = Instant.now();
            int page = 0;
            int size = 10;

            Pageable pageable = PageRequest.of(page, size);
            List<LogEntry> logEntries = Collections.singletonList(new LogEntry());
            Page<LogEntry> logPage = new PageImpl<>(logEntries, pageable, logEntries.size());

            when(logRepository.findLogsByUserIdAndLogTypeAndTimestampBetween(userId, logType, startDate, endDate, pageable))
                    .thenReturn(logPage);


            // When
            Page<LogEntryDTO> result = adminService.getUserLogs(userId, logType, startDate, endDate, page, size);

            // Then
            assertNotNull(result);
            assertEquals(1, result.getTotalElements());
            verify(logRepository, times(1)).findLogsByUserIdAndLogTypeAndTimestampBetween(userId, logType, startDate, endDate, pageable);
        }

        @Test
        @WithMockUser(roles = "ADMIN")
        @DisplayName("관리자 권한으로 로그 조회 시 로그가 없을 때 => 빈 페이지 반환")
        void testGetUserLogsNoLogs() {
            // Given
            Long userId = 1L;
            LogType logType = LogType.LOGIN_SUCCESS;
            Instant startDate = Instant.now().minusSeconds(3600);
            Instant endDate = Instant.now();
            int page = 0;
            int size = 10;

            Pageable pageable = PageRequest.of(page, size);
            Page<LogEntry> emptyLogPage = new PageImpl<>(Collections.emptyList(), pageable, 0);

            when(logRepository.findLogsByUserIdAndLogTypeAndTimestampBetween(userId, logType, startDate, endDate, pageable))
                    .thenReturn(emptyLogPage);

            // When
            Page<LogEntryDTO> result = adminService.getUserLogs(userId, logType, startDate, endDate, page, size);

            // Then
            assertNotNull(result);
            assertEquals(0, result.getTotalElements());
            verify(logRepository, times(1)).findLogsByUserIdAndLogTypeAndTimestampBetween(userId, logType, startDate, endDate, pageable);
        }
    }
}

