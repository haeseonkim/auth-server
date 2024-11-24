package com.abab.auth.util;

import lombok.Getter;

@Getter
public enum LogType {
    SIGNUP("SIGNUP"),
    LOGIN_SUCCESS("LOGIN_SUCCESS"),
    LOGIN_FAILURE("LOGIN_FAILURE"),
    LOGOUT("LOGOUT");

    private final String value;

    LogType(String value) {
        this.value = value;
    }
}