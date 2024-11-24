package com.abab.auth.global;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

public class ResponseHelper {
    private ResponseHelper() {
        throw new IllegalStateException("Response helper class");
    }

    public static <T> ResponseEntity<ResponseWrapper<T>> createResponse(T data, String status, HttpStatus httpStatus) {
        ResponseWrapper<T> responseWrapper = new ResponseWrapper<>(data, status);
        return new ResponseEntity<>(responseWrapper, httpStatus);
    }

    public static ResponseEntity<ResponseWrapper<Object>> createErrorResponse(ErrorDetails errorDetails, HttpStatus httpStatus) {
        ResponseWrapper<Object> responseWrapper = new ResponseWrapper<>(errorDetails, "error");
        return new ResponseEntity<>(responseWrapper, httpStatus);
    }
}
