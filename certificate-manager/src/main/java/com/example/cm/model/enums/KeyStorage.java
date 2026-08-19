package com.example.cm.model.enums;

/**
 * Where the private key material of a CA is kept. DATABASE stores the key
 * PEM in the platform database (the default); PKCS11 keeps the private key
 * token-resident on a PKCS#11 device so it never leaves the hardware.
 */
public enum KeyStorage {
    DATABASE,
    PKCS11
}
