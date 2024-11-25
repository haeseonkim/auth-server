package com.abab.auth.service;

import com.abab.auth.model.LogEntry;
import com.abab.auth.model.LogEntryDTO;
import com.abab.auth.repository.LogRepository;
import com.abab.auth.util.LogType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.test.context.support.WithMockUser;

import java.time.Instant;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
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

    @Nested
    @DisplayName("ExpireUserTokensTests")
    class ExpireUserTokensTests {

        @Test
        @DisplayName("유저의 모든 토큰 만료 시 성공 로그 생성")
        void testExpireUserTokensSuccess() {
            // Given
            Long userId = 1L;

            // When
            adminService.expireUserTokens(userId);

            // Then
            verify(logRepository, times(1)).save(any(LogEntry.class));
        }
    }

    @Nested
    @DisplayName("IsTokenValidTests")
    class IsTokenValidTests {

        @Test
        @DisplayName("만료되지 않은 토큰 => 유효")
        void testIsTokenValid() {
            // Given
            Long userId = 1L;
            Instant issueTime = Instant.now();

            // When
            boolean isValid = adminService.isTokenValid(userId, issueTime);

            // Then
            assertTrue(isValid, "Not expired token must be valid");
        }

        @Test
        @DisplayName("만료된 토큰 => 유효하지 않음")
        void testIsTokenInvalid() {
            // Given
            Long userId = 1L;
            adminService.expireUserTokens(userId);
            Instant expiredTime = Instant.now().minusSeconds(60);

            // When
            boolean isValid = adminService.isTokenValid(userId, expiredTime);

            // Then
            assertFalse(isValid, "Expired token must be invalid");
        }
    }

}

