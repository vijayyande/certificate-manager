package com.example.cm.model.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * A single tamper-evident audit entry. Each entry carries the SHA-256 hash of
 * the previous entry (hash chain) and an HMAC-SHA256 signature over its own
 * content, so any modification or reordering of the log is detectable.
 */
@Entity
@Table(name = "audit_log")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private LocalDateTime timestamp;

    @Column(length = 100)
    private String actor;

    @Column(length = 40)
    private String category;

    @Column(length = 60)
    private String action;

    @Column(columnDefinition = "TEXT")
    private String detail;

    /** SHA-256 of the previous entry, hex; "" for the first entry. */
    @Column(length = 64)
    private String prevHash;

    /** SHA-256 of this entry's payload, hex. */
    @Column(length = 64)
    private String hash;

    /** HMAC-SHA256 of this entry's payload with the app audit secret, hex. */
    @Column(length = 64)
    private String signature;
}
