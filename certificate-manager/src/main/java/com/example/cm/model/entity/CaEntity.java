package com.example.cm.model.entity;

import com.example.cm.model.enums.CaType;
import com.example.cm.model.enums.CertificateStatus;
import com.example.cm.model.enums.KeyStorage;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.ser.std.ToStringSerializer;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigInteger;
import java.time.LocalDateTime;

@Entity
@Table(name = "ca_registry")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CaEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String name;

    @Column(nullable = false)
    private String subjectDn;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private CaType caType;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private CertificateStatus status = CertificateStatus.PENDING;

    @JsonSerialize(using = ToStringSerializer.class)
    @Column(length = 80)
    private String serialNumber;

    @Column(columnDefinition = "TEXT")
    private String certificatePem;

    @Column(columnDefinition = "TEXT")
    private String privateKeyPem;

    /** Where this CA's private key lives: database (default) or a PKCS#11 device. */
    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    private KeyStorage keyStorage = KeyStorage.DATABASE;

    /** Token alias under which the CA key + certificate are stored on a PKCS#11 device. */
    @Column(length = 200)
    private String pkcs11Alias;

    private String keyAlgorithm;

    private Integer keySize;

    private String signatureAlgorithm;

    private LocalDateTime validFrom;

    private LocalDateTime validTo;

    private Long parentCaId;

    private String crlDistributionPoint;

    private String ocspUrl;

    private String requestedBy;

    private String approverName;

    private LocalDateTime createdAt;

    private LocalDateTime issuedAt;
}
