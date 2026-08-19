package com.example.cm.model.dto;

import java.util.List;

/**
 * A known PKCS#11 provider configuration that administrators can load as a
 * starting point and then adjust. {@code libraryPaths} lists known locations
 * across operating systems; {@code libraryPath} is the recommended default for
 * the current server platform.
 */
public record Pkcs11Preset(
        String name,
        String description,
        String providerName,
        List<String> libraryPaths,
        String libraryPath,
        Integer slotIndex) {
}
