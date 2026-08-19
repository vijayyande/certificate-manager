package com.example.cm.model.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * An arbitrary X.509 extension (additional OID). {@code type} controls how
 * {@code value} is encoded: STRING (DER UTF8String), INTEGER (ASN1Integer),
 * BOOLEAN (DERBoolean) or OCTETS (base64 decoded into DEROctetString).
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class CustomExtension {

    private String oid;

    private String type;

    private String value;
}
