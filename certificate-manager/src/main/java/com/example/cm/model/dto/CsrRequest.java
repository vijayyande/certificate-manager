package com.example.cm.model.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class CsrRequest {

    @NotBlank(message = "CSR (PKCS#10) in PEM format is required")
    private String csrPem;

    private Long issuerCaId;

    private String requestedBy;

}
