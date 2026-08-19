package com.example.dmz.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ResponderExceptionHandler {

    @ExceptionHandler(ResponderException.class)
    public ResponseEntity<String> handleResponder(ResponderException e) {
        return text(e.getStatus(), e.getMessage());
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<String> handleUnreadable(HttpMessageNotReadableException e) {
        return text(HttpStatus.BAD_REQUEST, "Invalid request body");
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<String> handleMissingParam(MissingServletRequestParameterException e) {
        return text(HttpStatus.BAD_REQUEST, "Missing required parameter: " + e.getParameterName());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleGeneric(Exception e) {
        return text(HttpStatus.INTERNAL_SERVER_ERROR, "Internal server error");
    }

    private ResponseEntity<String> text(HttpStatus status, String message) {
        return ResponseEntity.status(status)
                .contentType(MediaType.TEXT_PLAIN)
                .body(message);
    }
}
