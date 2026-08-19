package com.example.cm.model.dto;

import com.example.cm.model.enums.KeyStorage;
import lombok.Data;

@Data
public class Pkcs11SettingsRequest {

    private String providerName;

    private String libraryPath;

    private Integer slotIndex;

    private String tokenPin;

    private boolean enabled;

    /** Default key storage for newly requested CAs (DATABASE or PKCS11). */
    private KeyStorage keyStorageDefault;
}
