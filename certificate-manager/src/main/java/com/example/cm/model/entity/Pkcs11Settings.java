package com.example.cm.model.entity;

import com.example.cm.model.enums.KeyStorage;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Persisted PKCS#11 configuration (singleton row, id = 1). The admin configures
 * the provider library, slot and PIN here, and chooses whether newly requested
 * CAs store their private keys in the database or on the PKCS#11 device.
 */
@Entity
@Table(name = "pkcs11_settings")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Pkcs11Settings {

    @Id
    private Long id;

    @Column(length = 100)
    private String providerName;

    @Column(length = 500)
    private String libraryPath;

    private Integer slotIndex;

    @Column(length = 200)
    @JsonIgnore
    private String tokenPin;

    private boolean enabled;

    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    private KeyStorage keyStorageDefault = KeyStorage.DATABASE;

    private LocalDateTime createdAt;

    private LocalDateTime updatedAt;
}
