package com.example.cm.model.entity;

import com.example.cm.model.enums.KeyStorage;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * A reusable certificate profile. Contains all certificate parameters so a
 * requester can pick a profile instead of entering every field by hand.
 */
@Entity
@Table(name = "certificate_profiles", uniqueConstraints = @UniqueConstraint(columnNames = "name"))
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertificateProfile {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 100)
    private String name;

    @Column(length = 500)
    private String description;

    /** Built-in profile type (see {@link com.example.cm.model.enums.ProfileType}). */
    @Column(length = 30)
    private String type = "CUSTOM";

    @Column(nullable = false, length = 20)
    private String keyAlgorithm;

    @Column(nullable = false)
    private Integer keySize;

    @Column(nullable = false)
    private Integer validityDays;

    /** Fine-grained validity in minutes (null when validityDays is used). */
    private Integer validityMinutes;

    /** Profile produces CA certificates (basicConstraints CA:TRUE). Only administrators may use these. */
    @Column(nullable = false)
    private boolean caProfile;

    /** Where the platform-generated key pair is stored: DATABASE (exportable PEM) or PKCS11 (token-resident). */
    @Enumerated(EnumType.STRING)
    @Builder.Default
    @Column(length = 20)
    private KeyStorage keyStorage = KeyStorage.DATABASE;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "profile_key_usages", joinColumns = @JoinColumn(name = "profile_id"))
    @Column(name = "key_usage")
    private List<String> keyUsage = new ArrayList<>();

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "profile_extended_key_usages", joinColumns = @JoinColumn(name = "profile_id"))
    @Column(name = "extended_key_usage")
    private List<String> extendedKeyUsage = new ArrayList<>();

    @Convert(converter = CustomExtensionConverter.class)
    @Column(columnDefinition = "TEXT")
    private List<CustomExtension> additionalExtensions = new ArrayList<>();

    private String createdBy;

    private LocalDateTime createdAt;

    private LocalDateTime updatedAt;
}
