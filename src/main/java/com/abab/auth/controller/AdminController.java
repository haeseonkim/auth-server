package com.abab.auth.controller;

import com.abab.auth.model.LogEntryDTO;
import com.abab.auth.service.AdminService;
import com.abab.auth.util.LogType;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/v1/auth/admin")
public class AdminController {
    private final AdminService adminService;

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/users/{userId}/logs")
    public ResponseEntity<Page<LogEntryDTO>> getUserLogs(
            @PathVariable Long userId,
            @RequestParam(required = false) LogType logType,
            @RequestParam(required = false) Instant startDate,
            @RequestParam(required = false) Instant endDate,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size
    ) {
        Page<LogEntryDTO> userLogs = adminService.getUserLogs(userId, logType, startDate, endDate, page, size);
        return ResponseEntity.ok(userLogs);
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @PostMapping("/users/{userId}/expire-tokens")
    public ResponseEntity<String> expireUserTokens(@PathVariable Long userId) {
        adminService.expireUserTokens(userId);
        return ResponseEntity.ok("success");
    }
}
