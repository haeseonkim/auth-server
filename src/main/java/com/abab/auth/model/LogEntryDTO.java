package com.abab.auth.model;

import com.abab.auth.util.LogType;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class LogEntryDTO {
    private Long userId;
    private LogType logType;
    private Instant timestamp;
    private String message;
}
