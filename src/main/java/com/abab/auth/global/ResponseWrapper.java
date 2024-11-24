package com.abab.auth.global;

public record ResponseWrapper<T>(T data, String status) {
}
