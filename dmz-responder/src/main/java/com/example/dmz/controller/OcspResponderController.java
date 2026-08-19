package com.example.dmz.controller;

import com.example.dmz.config.ResponderProperties;
import com.example.dmz.exception.ResponderException;
import com.example.dmz.service.ResponderService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;

/**
 * OCSP responder. Supports both RFC 6960 wire transports:
 * <ul>
 *   <li>POST with a raw DER {@code application/ocsp-request} body, and</li>
 *   <li>GET with the base64url-encoded request in the {@code request} query
 *       parameter (RFC 5019; {@code base64} is accepted as an alias).</li>
 * </ul>
 * Responses are DER {@code application/ocsp-response} bytes that are produced
 * (and signed) by the certificate manager and proxied verbatim.
 */
@RestController
@RequestMapping("/api/ocsp")
@RequiredArgsConstructor
public class OcspResponderController {

    private final ResponderService service;
    private final ResponderProperties properties;

    @PostMapping(consumes = {"application/ocsp-request", "application/octet-stream", "application/ocsp-response"},
            produces = "application/ocsp-response")
    public ResponseEntity<byte[]> post(@RequestBody byte[] body) {
        return respond(service.ocsp(body));
    }

    @GetMapping(produces = "application/ocsp-response")
    public ResponseEntity<byte[]> get(@RequestParam(value = "request", required = false) String request,
                                      @RequestParam(value = "base64", required = false) String base64) {
        String encoded = request != null ? request : base64;
        if (encoded == null || encoded.isBlank()) {
            throw new ResponderException(HttpStatus.BAD_REQUEST,
                    "Missing OCSP request (use the 'request' query parameter)");
        }
        return respond(service.ocsp(decodeOcspRequest(encoded)));
    }

    private ResponseEntity<byte[]> respond(byte[] responseDer) {
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("application/ocsp-response"))
                .header("Cache-Control", "public, max-age=" + properties.getOcspCacheSeconds())
                .body(responseDer);
    }

    private byte[] decodeOcspRequest(String encoded) {
        String value = encoded.trim();
        try {
            return base64UrlDecode(value);
        } catch (IllegalArgumentException urlSafeFailed) {
            try {
                return Base64.getDecoder().decode(value);
            } catch (IllegalArgumentException standardFailed) {
                throw new ResponderException(HttpStatus.BAD_REQUEST, "Invalid OCSP request encoding");
            }
        }
    }

    private byte[] base64UrlDecode(String value) {
        int padding = (4 - (value.length() % 4)) % 4;
        return Base64.getUrlDecoder().decode(value + "=".repeat(padding));
    }
}
