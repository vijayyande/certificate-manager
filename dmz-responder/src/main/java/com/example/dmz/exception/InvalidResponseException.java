package com.example.dmz.exception;

/**
 * Raised when the certificate manager returns bytes that are not structurally
 * valid CRL/OCSP data. Prevents garbage from ever entering the responder cache.
 */
public class InvalidResponseException extends RuntimeException {

    public InvalidResponseException(String message, Throwable cause) {
        super(message, cause);
    }
}
