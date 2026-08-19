package com.example.cm.model.dto;

/**
 * Result of verifying the tamper-evident audit chain. When {@code valid} is
 * true the whole log is intact; otherwise {@code failedAt} points to the first
 * entry whose hash/signature/chain link no longer matches.
 */
public record AuditVerificationResult(boolean valid, long total, long verified,
                                      Long failedAt, String message) {
}
