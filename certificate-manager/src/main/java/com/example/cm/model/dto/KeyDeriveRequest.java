package com.example.cm.model.dto;

import lombok.Data;

/**
 * Body of {@code POST /api/crypto/derive}: the algorithm and optional size to
 * validate. When {@code keySize} is omitted the platform default is applied.
 */
@Data
public class KeyDeriveRequest {

    private String keyAlgorithm;

    private Integer keySize;
}
