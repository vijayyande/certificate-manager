package com.example.cm.model.dto;

/**
 * A single selectable key size within a {@link KeyAlgorithmInfo}: the bit size,
 * a display label, the NIST curve for EC keys (null for other algorithms) and
 * the X.509 signature algorithm the platform uses for that key.
 */
public record KeySizeOption(
        int size,
        String label,
        String curve,
        String signatureAlgorithm) {
}
