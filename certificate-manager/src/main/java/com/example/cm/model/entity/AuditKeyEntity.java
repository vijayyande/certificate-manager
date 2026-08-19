package com.example.cm.model.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Singleton row (id = 1) holding the HMAC secret used to sign audit entries.
 * The secret is generated once on first use so the audit chain stays
 * verifiable across restarts.
 */
@Entity
@Table(name = "audit_key")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditKeyEntity {

    @Id
    private Long id;

    @Column(length = 512)
    @JsonIgnore
    private String hmacSecret;

    private LocalDateTime createdAt;
}
