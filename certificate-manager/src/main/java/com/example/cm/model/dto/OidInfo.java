package com.example.cm.model.dto;

/**
 * A well-known X.509 extension OID with a friendly label and the suggested value
 * {@code type} (STRING | INTEGER | BOOLEAN | OCTETS), as exposed by
 * {@code GET /api/crypto/oids}. Used by the UI to offer a dropdown of known OIDs
 * while still allowing arbitrary OIDs to be typed by hand.
 */
public record OidInfo(
        String oid,
        String label,
        String type) {
}
