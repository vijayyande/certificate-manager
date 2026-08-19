package com.example.cm.model.dto;

import com.example.cm.model.enums.CaType;
import com.example.cm.model.enums.KeyStorage;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class CaRequest {

    @NotBlank(message = "CA name is required")
    private String name;

    @NotBlank(message = "Subject DN is required (e.g. CN=My Root CA, O=Example Corp)")
    private String subjectDn;

    @NotNull(message = "CA type is required")
    private CaType caType;

    private Long parentCaId;

    private Integer validityDays;

    private String keyAlgorithm;

    private Integer keySize;

    /** DATABASE or PKCS11; when omitted the platform default from Settings is used. */
    private KeyStorage keyStorage;

    /** Token alias when keyStorage is PKCS11; defaults to the CA name. */
    private String pkcs11Alias;

    private String requestedBy;
}
