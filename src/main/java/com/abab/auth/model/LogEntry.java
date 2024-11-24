package com.abab.auth.model;

import com.abab.auth.util.LogType;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.*;

import java.time.Instant;

@Getter
@Entity
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LogEntry {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Long userId;
    private LogType logType; // e.g., SIGNUP, LOGIN_SUCCESS, LOGIN_FAILURE, LOGOUT
    private String message;
    private Instant timestamp; // 로그가 기록된 시간
}
