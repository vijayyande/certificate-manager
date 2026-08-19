package com.example.cm.model.dto;

import com.example.cm.model.entity.CustomExtension;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.util.List;

@Data
public class ManualCertificateRequest {

    @NotBlank(message = "Common name is required")
    @Size(max = 64, message = "Common name is too long")
    private String commonName;

    private String organization;

    private String organizationalUnit;

    private String country;

    private String state;

    private String locality;

    private String emailAddress;

    private String keyAlgorithm;

    private Integer keySize;

    private Integer validityDays;

    /** Optional fine-grained validity in minutes (1..525600). Takes precedence over validityDays. */
    private Integer validityMinutes;

    private List<String> dnsNames;

    private List<String> ipAddresses;

    private Long issuerCaId;

    private String requestedBy;

    /** Optional reusable certificate profile; its parameters act as defaults for this request. */
    private Long profileId;

    /** Additional custom extensions (OID + type + value) to embed in the issued certificate. */
    private List<CustomExtension> additionalExtensions;
}
