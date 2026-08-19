package com.example.cm.model.dto;

import java.util.List;

/**
 * Serialized view of a built-in profile type with its default parameters,
 * used by the UI to pre-fill the profile form.
 */
public record ProfileTypeInfo(
        String code,
        String description,
        String keyAlgorithm,
        Integer keySize,
        Integer validityDays,
        boolean caProfile,
        List<String> keyUsage,
        List<String> extendedKeyUsage) {
}
