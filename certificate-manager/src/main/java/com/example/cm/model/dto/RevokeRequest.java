package com.example.cm.model.dto;

import com.example.cm.model.enums.RevocationReason;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class RevokeRequest {

    @NotNull(message = "revocation reason is required")
    private RevocationReason reason;
}
