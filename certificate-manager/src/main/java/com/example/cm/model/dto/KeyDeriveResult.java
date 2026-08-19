package com.example.cm.model.dto;

/**
 * Result of {@code POST /api/crypto/derive}: the normalized algorithm, the
 * effective key size and the signature algorithm derived from both.
 */
public record KeyDeriveResult(
        String keyAlgorithm,
        int keySize,
        String signatureAlgorithm) {
}
