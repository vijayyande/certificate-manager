package com.example.cm.model.enums;

public enum RevocationReason {
    UNSPECIFIED("unspecified"),
    KEY_COMPROMISE("keyCompromise"),
    CA_COMPROMISE("cACompromise"),
    AFFILIATION_CHANGED("affiliationChanged"),
    SUPERSEDED("superseded"),
    CESSATION_OF_OPERATION("cessationOfOperation"),
    CERTIFICATE_HOLD("certificateHold"),
    REMOVE_FROM_CRL("removeFromCRL"),
    PRIVILEGE_WITHDRAWN("privilegeWithdrawn"),
    AA_COMPROMISE("aACompromise");

    private final String rfcValue;

    RevocationReason(String rfcValue) {
        this.rfcValue = rfcValue;
    }

    public String rfcValue() {
        return rfcValue;
    }
}
