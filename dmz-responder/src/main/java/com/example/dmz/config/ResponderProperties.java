package com.example.dmz.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * All settings for the DMZ responder. Every field maps to a {@code cm.*}
 * property and has a sensible default so the app can be configured entirely
 * through environment variables.
 */
@Data
@ConfigurationProperties(prefix = "cm")
public class ResponderProperties {

    /** Internal certificate-manager base URL (e.g. https://cm.internal/api). */
    private String baseUrl = "http://localhost:8443";

    /** Service account used to call the certificate manager. */
    private String username = "responder";

    private String password = "";

    /** TTL for cached CRLs in seconds. */
    private int crlCacheSeconds = 300;

    /** TTL for cached OCSP responses in seconds. */
    private int ocspCacheSeconds = 60;

    /** TTL for the cached active-CA list in seconds. */
    private int caListCacheSeconds = 300;

    /** Maximum accepted OCSP request size in bytes. */
    private int maxOcspRequestBytes = 16384;

    /** Connect timeout towards the certificate manager. */
    private int connectTimeoutMs = 5000;

    /** Read timeout towards the certificate manager. */
    private int readTimeoutMs = 10000;

    /** Serve stale cached entries when the backend is unreachable. */
    private boolean serveStaleOnError = true;
}
