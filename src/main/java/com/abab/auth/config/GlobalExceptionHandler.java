package com.abab.auth.config;

import com.abab.auth.global.ErrorDetails;
import com.abab.auth.global.ResponseHelper;
import com.abab.auth.global.ResponseWrapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.server.ResponseStatusException;

@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<ResponseWrapper<Object>> handleResponseStatusException(ResponseStatusException ex) {
        ErrorDetails errorDetails = new ErrorDetails(ex.getStatusCode().value(), ex.getReason());
        return ResponseHelper.createErrorResponse(errorDetails, (HttpStatus) ex.getStatusCode());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ResponseWrapper<Object>> handleGeneralException(Exception ex) {
        ErrorDetails errorDetails = new ErrorDetails(HttpStatus.INTERNAL_SERVER_ERROR.value(), ex.getMessage());
        return ResponseHelper.createErrorResponse(errorDetails, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
