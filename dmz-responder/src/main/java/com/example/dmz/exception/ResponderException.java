package com.example.dmz.exception;

import org.springframework.http.HttpStatus;

/**
 * Client-facing error carrying the HTTP status the responder should answer with.
 */
public class ResponderException extends RuntimeException {

    private final HttpStatus status;

    public ResponderException(HttpStatus status, String message) {
        super(message);
        this.status = status;
    }

    public HttpStatus getStatus() {
        return status;
    }
}
