package com.example.cm.model.dto;

import java.util.List;

/**
 * A supported key algorithm and its configurable parameters, as exposed by
 * {@code GET /api/crypto/algorithms}. One entry per algorithm.
 */
public record KeyAlgorithmInfo(
        String name,
        String label,
        int defaultKeySize,
        boolean fixedSize,
        String description,
        List<KeySizeOption> keySizeOptions) {
}
