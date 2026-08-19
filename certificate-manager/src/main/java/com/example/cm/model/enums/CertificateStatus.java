package com.example.cm.model.enums;

public enum CertificateStatus {
    PENDING,     // legacy: retained for data compatibility
    APPROVED,    // legacy: retained for data compatibility
    ISSUED,      // active certificate
    SUSPENDED,   // temporarily suspended
    REVOKED,     // permanently revoked
    REJECTED,    // legacy: issuance failed or was denied
    EXPIRED
}
