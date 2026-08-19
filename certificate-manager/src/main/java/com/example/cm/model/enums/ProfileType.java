package com.example.cm.model.enums;

import java.util.List;

/**
 * Built-in certificate profile types. Each preset bundles a sensible key
 * algorithm, key size, validity, key usage and extended key usage so a
 * profile can be created with a single type instead of hand-picking every
 * field. CUSTOM leaves every field to the administrator.
 */
public enum ProfileType {

    CUSTOM(null, null, 0, false, List.of(), List.of(),
            "Free-form profile; every field is defined by the administrator."),
    CA("RSA", 3072, 3650, true, List.of("keyCertSign", "cRLSign"), List.of(),
            "Root / intermediate CA profile. Administrators only."),
    SERVER("RSA", 2048, 825, false, List.of("digitalSignature", "keyEncipherment"), List.of("serverAuth"),
            "TLS server certificate."),
    CLIENT("RSA", 2048, 365, false, List.of("digitalSignature"), List.of("clientAuth"),
            "Client authentication for end users or devices."),
    CODE_SIGNING("RSA", 2048, 365, false, List.of("digitalSignature", "nonRepudiation"), List.of("codeSigning"),
            "Code signing certificate for signing binaries and scripts."),
    EMAIL("RSA", 2048, 365, false, List.of("digitalSignature", "keyEncipherment"), List.of("emailProtection"),
            "Email protection (S/MIME) certificate."),
    DOCUMENT_SIGNING("RSA", 2048, 365, false, List.of("digitalSignature", "nonRepudiation"), List.of("emailProtection"),
            "Document signing certificate (e.g. PDF signing)."),
    CLASS_1("RSA", 2048, 365, false, List.of("digitalSignature", "keyEncipherment"),
            List.of("clientAuth", "emailProtection"), "Class 1 individual validation certificate."),
    CLASS_2("RSA", 2048, 365, false, List.of("digitalSignature", "nonRepudiation", "keyEncipherment"),
            List.of("clientAuth", "emailProtection"), "Class 2 individual / organization validation certificate."),
    CLASS_3("RSA", 3072, 730, false, List.of("digitalSignature", "nonRepudiation", "keyEncipherment", "keyAgreement"),
            List.of("serverAuth", "clientAuth", "codeSigning", "emailProtection"),
            "Class 3 high-assurance validation certificate."),
    AADHAAR_ESIGN("RSA", 2048, 365, false, List.of("digitalSignature", "nonRepudiation"), List.of("emailProtection"),
            "Aadhaar eSign certificate for digitally signing documents.");

    private final String keyAlgorithm;
    private final Integer keySize;
    private final Integer validityDays;
    private final boolean caProfile;
    private final List<String> keyUsage;
    private final List<String> extendedKeyUsage;
    private final String description;

    ProfileType(String keyAlgorithm, Integer keySize, Integer validityDays, boolean caProfile,
                List<String> keyUsage, List<String> extendedKeyUsage, String description) {
        this.keyAlgorithm = keyAlgorithm;
        this.keySize = keySize;
        this.validityDays = validityDays;
        this.caProfile = caProfile;
        this.keyUsage = keyUsage;
        this.extendedKeyUsage = extendedKeyUsage;
        this.description = description;
    }

    public String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public Integer getKeySize() {
        return keySize;
    }

    public Integer getValidityDays() {
        return validityDays;
    }

    public boolean isCaProfile() {
        return caProfile;
    }

    public List<String> getKeyUsage() {
        return keyUsage;
    }

    public List<String> getExtendedKeyUsage() {
        return extendedKeyUsage;
    }

    public String getDescription() {
        return description;
    }

    public static ProfileType fromString(String value) {
        if (value == null || value.isBlank()) {
            return CUSTOM;
        }
        for (ProfileType type : values()) {
            if (type.name().equalsIgnoreCase(value.trim())) {
                return type;
            }
        }
        return CUSTOM;
    }
}
