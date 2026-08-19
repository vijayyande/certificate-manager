package com.example.cm.model.dto;

import com.example.cm.model.entity.CustomExtension;
import com.example.cm.model.enums.KeyStorage;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class ProfileRequest {

    @NotBlank(message = "Profile name is required")
    private String name;

    private String description;

    /** Built-in profile type; e.g. CODE_SIGNING, EMAIL, CLASS_2, AADHAAR_ESIGN. Omitted/unknown means CUSTOM. */
    private String type;

    private String keyAlgorithm;

    private Integer keySize;

    private Integer validityDays;

    /** Optional fine-grained validity in minutes (1..525600). Takes precedence over validityDays. */
    private Integer validityMinutes;

    private Boolean caProfile;

    /** Where platform-generated keys go: DATABASE (PEM, default) or PKCS11 (token-resident). */
    private KeyStorage keyStorage;

    private List<String> keyUsage = new ArrayList<>();

    private List<String> extendedKeyUsage = new ArrayList<>();

    private List<CustomExtension> additionalExtensions = new ArrayList<>();
}
