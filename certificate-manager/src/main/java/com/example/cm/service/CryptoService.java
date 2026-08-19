package com.example.cm.service;

import com.example.cm.exception.BusinessException;
import com.example.cm.model.dto.KeyAlgorithmInfo;
import com.example.cm.model.dto.KeyDeriveResult;
import com.example.cm.model.dto.KeySizeOption;
import com.example.cm.model.dto.OidInfo;
import com.example.cm.model.entity.CustomExtension;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
public class CryptoService {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static final String RSA = "RSA";
    public static final String EC = "EC";
    public static final String ED25519 = "ED25519";
    public static final String ED448 = "ED448";

    private final String crlUrlBase;
    private final String ocspUrl;

    public CryptoService(@Value("${cm.crl.url-base}") String crlUrlBase,
                         @Value("${cm.ocsp-url}") String ocspUrl) {
        this.crlUrlBase = crlUrlBase;
        this.ocspUrl = ocspUrl;
    }

    public String getCrlUrlBase() {
        return crlUrlBase;
    }

    public String getOcspUrl() {
        return ocspUrl;
    }

    public KeyPair generateKeyPair(String algorithm, int keySize) {
        try {
            String alg = normalizeKeyAlgorithm(algorithm);
            switch (alg) {
                case EC -> {
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                    kpg.initialize(new ECGenParameterSpec(curveFor(keySize)));
                    return kpg.generateKeyPair();
                }
                case ED25519 -> {
                    return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
                }
                case ED448 -> {
                    return KeyPairGenerator.getInstance("Ed448").generateKeyPair();
                }
                default -> {
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                    kpg.initialize(keySize > 0 ? keySize : 2048);
                    return kpg.generateKeyPair();
                }
            }
        } catch (Exception e) {
            throw new BusinessException("Failed to generate key pair: " + e.getMessage(), e);
        }
    }

    /**
     * Canonicalize a key algorithm name (RSA, EC/ECDSA, ED25519, ED448) into the
     * platform's stored representation. Unsupported algorithms are rejected.
     */
    public String normalizeKeyAlgorithm(String algorithm) {
        if (algorithm == null || algorithm.isBlank()) {
            return RSA;
        }
        return switch (algorithm.trim().toUpperCase()) {
            case "RSA" -> RSA;
            case "EC", "ECDSA" -> EC;
            case "ED25519" -> ED25519;
            case "ED448" -> ED448;
            default -> throw new BusinessException("Unsupported key algorithm: " + algorithm);
        };
    }

    /** Default key size for an algorithm when none is supplied. */
    public int defaultKeySizeFor(String algorithm) {
        return switch (normalizeKeyAlgorithm(algorithm)) {
            case EC, ED25519 -> 256;
            case ED448 -> 456;
            default -> 2048;
        };
    }

    /** Whether the given key size is valid for the algorithm. */
    public boolean isSupportedKeySize(String algorithm, int keySize) {
        return switch (normalizeKeyAlgorithm(algorithm)) {
            case RSA -> keySize == 2048 || keySize == 3072 || keySize == 4096;
            case EC -> keySize == 256 || keySize == 384 || keySize == 521;
            case ED25519 -> keySize == 256;
            case ED448 -> keySize == 456;
            default -> false;
        };
    }

    /** Human readable validation error for an algorithm's key size. */
    public String keySizeValidationMessage(String algorithm) {
        return switch (normalizeKeyAlgorithm(algorithm)) {
            case RSA -> "RSA key size must be 2048, 3072 or 4096";
            case EC -> "EC curve must be P-256 (256), P-384 (384) or P-521 (521)";
            case ED25519 -> "Ed25519 keys have a fixed size of 256 bits";
            case ED448 -> "Ed448 keys have a fixed size of 456 bits";
            default -> "Unsupported key algorithm";
        };
    }

    /** NIST curve name for an EC key size (bits): 384 -&gt; P-384, 521 -&gt; P-521, else P-256. */
    public String curveFor(int keySize) {
        if (keySize >= 521) {
            return "secp521r1";
        }
        if (keySize >= 384) {
            return "secp384r1";
        }
        return "secp256r1";
    }

    public PKCS10CertificationRequest parseCsr(String csrPem) {
        try (PEMParser parser = new PEMParser(new StringReader(normalizePem(csrPem)))) {
            Object obj = parser.readObject();
            if (!(obj instanceof PKCS10CertificationRequest csr)) {
                throw new BusinessException("Provided PEM does not contain a PKCS#10 CSR");
            }
            return csr;
        } catch (IOException e) {
            throw new BusinessException("Unable to parse CSR: " + e.getMessage(), e);
        }
    }

    public JcaPKCS10CertificationRequest jcaCsr(PKCS10CertificationRequest csr) {
        try {
            return new JcaPKCS10CertificationRequest(csr);
        } catch (Exception e) {
            throw new BusinessException("Unable to read CSR details: " + e.getMessage(), e);
        }
    }

    public PublicKey extractPublicKey(PKCS10CertificationRequest csr) {
        try {
            return jcaCsr(csr).getPublicKey();
        } catch (Exception e) {
            throw new BusinessException("Unable to extract public key from CSR: " + e.getMessage(), e);
        }
    }

    public PKCS10CertificationRequest buildCsr(X500Name subject, List<GeneralName> subjectAltNames,
                                               KeyPair keyPair, String signatureAlgorithm) {
        return buildCsr(subject, subjectAltNames, keyPair, signatureAlgorithm, null);
    }

    /**
     * Build a PKCS#10 CSR. When {@code signerProvider} is null the request is
     * signed with Bouncy Castle; otherwise the named provider (e.g. SunPKCS11)
     * signs it, which is required for token-resident keys.
     */
    public PKCS10CertificationRequest buildCsr(X500Name subject, List<GeneralName> subjectAltNames,
                                               KeyPair keyPair, String signatureAlgorithm, String signerProvider) {
        try {
            JcaPKCS10CertificationRequestBuilder builder =
                    new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());
            if (subjectAltNames != null && !subjectAltNames.isEmpty()) {
                GeneralNames names = new GeneralNames(subjectAltNames.toArray(new GeneralName[0]));
                Extensions extensions = new Extensions(new Extension[]{
                        new Extension(Extension.subjectAlternativeName, false,
                                new DEROctetString(names))
                });
                builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions);
            }
            JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(signatureAlgorithm);
            if (signerProvider != null) {
                contentSignerBuilder.setProvider(signerProvider);
            } else {
                contentSignerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
            }
            ContentSigner signer = contentSignerBuilder.build(keyPair.getPrivate());
            return builder.build(signer);
        } catch (Exception e) {
            throw new BusinessException("Failed to build CSR: " + e.getMessage(), e);
        }
    }

    public GeneralNames sansFromCsr(PKCS10CertificationRequest csr) {
        Attribute[] attrs = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        for (Attribute attr : attrs) {
            for (ASN1Encodable value : attr.getAttributeValues()) {
                Extensions extensions = Extensions.getInstance(value);
                Extension san = extensions.getExtension(Extension.subjectAlternativeName);
                if (san != null) {
                    return GeneralNames.getInstance(san.getParsedValue());
                }
            }
        }
        return null;
    }

    public String signatureAlgorithmFor(String keyAlgorithm) {
        return signatureAlgorithmFor(keyAlgorithm, 0);
    }

    public String signatureAlgorithmFor(String keyAlgorithm, int keySize) {
        return switch (normalizeKeyAlgorithm(keyAlgorithm)) {
            case ED25519 -> "Ed25519";
            case ED448 -> "Ed448";
            case EC -> {
                if (keySize >= 521) {
                    yield "SHA512withECDSA";
                }
                if (keySize >= 384) {
                    yield "SHA384withECDSA";
                }
                yield "SHA256withECDSA";
            }
            default -> "SHA256withRSA";
        };
    }

    /**
     * Catalog of supported key algorithms for {@code GET /api/crypto/algorithms}.
     * Single source of truth for the UI selects and client-side validation.
     */
    public List<KeyAlgorithmInfo> keyAlgorithmCatalog() {
        return List.of(
                new KeyAlgorithmInfo(RSA, "RSA", 2048, false,
                        "RSA with 2048, 3072 or 4096-bit keys",
                        List.of(
                                new KeySizeOption(2048, "RSA 2048", null, signatureAlgorithmFor(RSA, 2048)),
                                new KeySizeOption(3072, "RSA 3072", null, signatureAlgorithmFor(RSA, 3072)),
                                new KeySizeOption(4096, "RSA 4096", null, signatureAlgorithmFor(RSA, 4096)))),
                new KeyAlgorithmInfo(EC, "ECDSA", 256, false,
                        "NIST elliptic curves: P-256, P-384, P-521",
                        List.of(
                                new KeySizeOption(256, "P-256", "secp256r1", signatureAlgorithmFor(EC, 256)),
                                new KeySizeOption(384, "P-384", "secp384r1", signatureAlgorithmFor(EC, 384)),
                                new KeySizeOption(521, "P-521", "secp521r1", signatureAlgorithmFor(EC, 521)))),
                new KeyAlgorithmInfo(ED25519, "Ed25519", 256, true,
                        "Ed25519 (Curve25519) - fixed 256-bit key",
                        List.of(new KeySizeOption(256, "256 (fixed)", null, signatureAlgorithmFor(ED25519, 256)))),
                new KeyAlgorithmInfo(ED448, "Ed448", 456, true,
                        "Ed448 (Curve448) - fixed 456-bit key",
                        List.of(new KeySizeOption(456, "456 (fixed)", null, signatureAlgorithmFor(ED448, 456)))));
    }

    /**
     * Catalog of well-known X.509 extension OIDs for {@code GET /api/crypto/oids}.
     * Drives the dropdown in the request/profile editors while leaving room for
     * arbitrary OIDs typed by hand. {@code type} is the suggested value type.
     */
    public List<OidInfo> oidCatalog() {
        return List.of(
                new OidInfo("2.5.29.14", "Subject Key Identifier", "OCTETS"),
                new OidInfo("2.5.29.15", "Key Usage", "STRING"),
                new OidInfo("2.5.29.17", "Subject Alternative Name", "STRING"),
                new OidInfo("2.5.29.18", "Issuer Alternative Name", "STRING"),
                new OidInfo("2.5.29.19", "Basic Constraints", "STRING"),
                new OidInfo("2.5.29.29", "Certificate Issuer", "STRING"),
                new OidInfo("2.5.29.31", "CRL Distribution Points", "STRING"),
                new OidInfo("2.5.29.32", "Certificate Policies", "STRING"),
                new OidInfo("2.5.29.35", "Authority Key Identifier", "OCTETS"),
                new OidInfo("2.5.29.36", "Policy Constraints", "STRING"),
                new OidInfo("2.5.29.37", "Extended Key Usage", "STRING"),
                new OidInfo("2.5.29.46", "Name Constraints", "STRING"),
                new OidInfo("1.3.6.1.5.5.7.1.1", "Authority Information Access", "STRING"),
                new OidInfo("1.3.6.1.5.5.7.1.3", "Qualified Certificates (QC Statements)", "STRING"),
                new OidInfo("1.3.6.1.5.5.7.48.1.5", "OCSP No Check", "OCTETS"),
                new OidInfo("1.3.6.1.5.5.7.3.1", "EKU: TLS Server Authentication", "STRING"),
                new OidInfo("1.3.6.1.5.5.7.3.2", "EKU: TLS Client Authentication", "STRING"),
                new OidInfo("1.3.6.1.5.5.7.3.3", "EKU: Code Signing", "STRING"),
                new OidInfo("1.3.6.1.5.5.7.3.4", "EKU: E-mail Protection", "STRING"),
                new OidInfo("1.3.6.1.5.5.7.3.6", "EKU: IPsec End System", "STRING"),
                new OidInfo("1.3.6.1.5.5.7.3.8", "EKU: Time Stamping", "STRING"),
                new OidInfo("1.3.6.1.5.5.7.3.9", "EKU: OCSP Signing", "STRING"),
                new OidInfo("1.2.840.113549.1.9.15", "SMIME Capabilities", "STRING"),
                new OidInfo("1.3.6.1.4.1.311.20.2", "MS Certificate Template Name", "STRING"),
                new OidInfo("1.3.6.1.4.1.311.21.7", "MS Certificate Template Information", "OCTETS"),
                new OidInfo("1.3.6.1.4.1.11129.2.4.2", "Certificate Transparency SCT List", "OCTETS"),
                new OidInfo("2.16.840.1.113730.1.1", "Netscape Certificate Type", "STRING"),
                new OidInfo("2.16.840.1.113730.1.13", "Netscape Comment", "STRING"),
                new OidInfo("2.5.4.3", "Common Name", "STRING"),
                new OidInfo("2.5.4.11", "Organizational Unit", "STRING"),
                new OidInfo("2.5.4.6", "Country Name", "STRING"),
                new OidInfo("2.5.4.10", "Organization Name", "STRING"),
                new OidInfo("1.2.840.113549.1.9.1", "E-mail Address", "STRING"));
    }

    /**
     * Resolve the effective key size for an algorithm: defaults when none is
     * supplied and rejects unsupported sizes. Used by every entry point so the
     * CA / profile / certificate / derive flows stay consistent.
     */
    public int resolveKeySize(String algorithm, Integer requestedSize) {
        String norm = normalizeKeyAlgorithm(algorithm);
        int size = requestedSize != null && requestedSize > 0 ? requestedSize : defaultKeySizeFor(norm);
        if (!isSupportedKeySize(norm, size)) {
            throw new BusinessException(keySizeValidationMessage(norm));
        }
        return size;
    }

    /**
     * Validate an algorithm/size and derive the resulting parameters, as exposed
     * by {@code POST /api/crypto/derive}. Throws a BusinessException (mapped to
     * HTTP 400) when the algorithm or size is unsupported.
     */
    public KeyDeriveResult deriveKeyParameters(String algorithm, Integer requestedSize) {
        String norm = normalizeKeyAlgorithm(algorithm);
        int size = resolveKeySize(norm, requestedSize);
        return new KeyDeriveResult(norm, size, signatureAlgorithmFor(norm, size));
    }

    public X500Name subjectFromCsr(PKCS10CertificationRequest csr) {
        return csr.getSubject();
    }

    public String subjectDnFromCsr(PKCS10CertificationRequest csr) {
        return subjectFromCsr(csr).toString();
    }

    public String commonNameFromCsr(PKCS10CertificationRequest csr) {
        String dn = subjectDnFromCsr(csr);
        for (String part : dn.split(",")) {
            String trimmed = part.trim();
            if (trimmed.toLowerCase().startsWith("cn=")) {
                return trimmed.substring(3);
            }
        }
        return dn;
    }

    public String buildSelfSignedCaCertificate(String subjectDn, KeyPair caKeys,
                                               int validityDays, String signatureAlgorithm, boolean isCa,
                                               String signerProvider) {
        X500Name subject = new X500Name(subjectDn);
        BigInteger serial = new BigInteger(128, new SecureRandom()).abs();
        return buildCertificate(subject, subject, caKeys.getPublic(), caKeys.getPrivate(),
                caKeys.getPublic(), serial, validityDays * 86400L, signatureAlgorithm, isCa, null, null, null,
                null, null, null, signerProvider);
    }

    public String buildSignedCaCertificate(String subjectDn, KeyPair caKeys,
                                           X509CertificateHolder issuerCert, PrivateKey issuerKey,
                                           String issuerSigAlg, int validityDays, String signerProvider) {
        X500Name subject = new X500Name(subjectDn);
        BigInteger serial = new BigInteger(128, new SecureRandom()).abs();
        return buildCertificate(issuerCert.getSubject(), subject, caKeys.getPublic(), issuerKey,
                issuerPubKeyOf(issuerCert), serial, validityDays * 86400L, issuerSigAlg, true, null, null, null,
                null, null, null, signerProvider);
    }

    public String buildSignedCertificate(X509CertificateHolder issuerCert,
                                         PrivateKey issuerKey, String issuerSigAlg,
                                         PKCS10CertificationRequest csr, PublicKey subjectPublicKey,
                                         long validitySeconds) {
        return buildSignedCertificate(issuerCert, issuerKey, issuerSigAlg, csr, subjectPublicKey,
                validitySeconds, false, List.of(), List.of(), List.of(), null);
    }

    public String buildSignedCertificate(X509CertificateHolder issuerCert,
                                         PrivateKey issuerKey, String issuerSigAlg,
                                         PKCS10CertificationRequest csr, PublicKey subjectPublicKey,
                                         long validitySeconds, boolean isCa, List<String> keyUsage,
                                         List<String> extendedKeyUsage,
                                         List<CustomExtension> customExtensions, String signerProvider) {
        X500Name issuerName = issuerCert.getSubject();
        X500Name subjectName = csr.getSubject();
        BigInteger serial = new BigInteger(128, new SecureRandom()).abs();

        String crlUrl = crlUrlBase + issuerCert.getSerialNumber().toString(16);
        String ocsp = ocspUrl;

        return buildCertificate(issuerName, subjectName, subjectPublicKey, issuerKey,
                issuerPubKeyOf(issuerCert), serial, validitySeconds, issuerSigAlg, isCa, crlUrl, ocsp,
                sansFromCsr(csr), keyUsage, extendedKeyUsage, customExtensions, signerProvider);
    }

    private PublicKey issuerPubKeyOf(X509CertificateHolder issuerCert) {
        try {
            X509Certificate jca = new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(issuerCert);
            return jca.getPublicKey();
        } catch (Exception e) {
            throw new BusinessException("Unable to read issuer public key: " + e.getMessage(), e);
        }
    }

    private String buildCertificate(X500Name issuer, X500Name subject,
                                    PublicKey subjectPubKey, PrivateKey issuerPrivKey,
                                    PublicKey verifyKey, BigInteger serial, long validitySeconds,
                                    String signatureAlgorithm, boolean isCa, String crlDistPoint, String ocspUrl,
                                    GeneralNames subjectAltNames, List<String> keyUsageBits,
                                    List<String> ekuOids, List<CustomExtension> customExtensions,
                                    String signerProvider) {
        try {
            Date notBefore = new Date();
            Date notAfter = Date.from(Instant.now().plusSeconds(validitySeconds));

            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    issuer, serial, notBefore, notAfter, subject, subjectPubKey);

            Set<String> systemOids = new HashSet<>();
            systemOids.add(Extension.subjectKeyIdentifier.getId());
            systemOids.add(Extension.keyUsage.getId());
            systemOids.add(Extension.basicConstraints.getId());

            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            builder.addExtension(Extension.subjectKeyIdentifier, false,
                    extUtils.createSubjectKeyIdentifier(subjectPubKey));

            KeyUsage ku;
            if (keyUsageBits != null && !keyUsageBits.isEmpty()) {
                ku = new KeyUsage(parseKeyUsage(keyUsageBits));
            } else {
                ku = isCa ? new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign)
                        : new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment
                        | KeyUsage.dataEncipherment);
            }
            builder.addExtension(Extension.keyUsage, true, ku);

            if (isCa) {
                builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            } else {
                builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

                if (ekuOids != null && !ekuOids.isEmpty()) {
                    builder.addExtension(Extension.extendedKeyUsage, false, buildExtendedKeyUsage(ekuOids));
                } else {
                    builder.addExtension(Extension.extendedKeyUsage, false,
                            new ExtendedKeyUsage(new KeyPurposeId[]{
                                    KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth}));
                }
                systemOids.add(Extension.extendedKeyUsage.getId());

                if (subjectAltNames != null) {
                    builder.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);
                }
                systemOids.add(Extension.subjectAlternativeName.getId());

                if (crlDistPoint != null && !crlDistPoint.isBlank()) {
                    GeneralName gname = new GeneralName(GeneralName.uniformResourceIdentifier, crlDistPoint);
                    DistributionPointName dpn = new DistributionPointName(new GeneralNames(gname));
                    CRLDistPoint distPoint = new CRLDistPoint(new DistributionPoint[]{new DistributionPoint(dpn, null, null)});
                    builder.addExtension(Extension.cRLDistributionPoints, false, distPoint);
                    systemOids.add(Extension.cRLDistributionPoints.getId());
                }
                if (ocspUrl != null && !ocspUrl.isBlank()) {
                    AuthorityInformationAccess aia = new AuthorityInformationAccess(
                            new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1"),
                            new GeneralName(GeneralName.uniformResourceIdentifier, ocspUrl));
                    builder.addExtension(Extension.authorityInfoAccess, false, aia);
                    systemOids.add(Extension.authorityInfoAccess.getId());
                }
            }

            if (customExtensions != null) {
                Set<String> seenOids = new HashSet<>();
                for (CustomExtension ext : customExtensions) {
                    if (ext == null || ext.getOid() == null || ext.getOid().isBlank()) {
                        continue;
                    }
                    String oid = ext.getOid().trim();
                    if (systemOids.contains(oid)) {
                        throw new BusinessException("Custom extension OID " + oid
                                + " is already added automatically by the system. "
                                + "Remove it from additional extensions and use the certificate form instead.");
                    }
                    if (!seenOids.add(oid)) {
                        throw new BusinessException("Custom extension OID " + oid
                                + " is listed more than once. Each extension OID may be added only once.");
                    }
                    builder.addExtension(new ASN1ObjectIdentifier(oid), false, toAsn1Value(ext));
                }
            }

            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                    .setProvider(signerProvider == null || signerProvider.isBlank()
                            ? BouncyCastleProvider.PROVIDER_NAME : signerProvider)
                    .build(issuerPrivKey);

            X509CertificateHolder holder = builder.build(signer);
            X509Certificate cert = new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(holder);
            cert.verify(verifyKey);
            return toPem(cert);
        } catch (Exception e) {
            throw new BusinessException("Certificate generation failed: " + e.getMessage(), e);
        }
    }

    private int parseKeyUsage(List<String> names) {
        int bits = 0;
        for (String name : names) {
            switch (name == null ? "" : name.trim().toLowerCase()) {
                case "digitalsignature" -> bits |= KeyUsage.digitalSignature;
                case "nonrepudiation", "contentcommitment" -> bits |= KeyUsage.nonRepudiation;
                case "keyencipherment" -> bits |= KeyUsage.keyEncipherment;
                case "dataencipherment" -> bits |= KeyUsage.dataEncipherment;
                case "keyagreement" -> bits |= KeyUsage.keyAgreement;
                case "keycertsign" -> bits |= KeyUsage.keyCertSign;
                case "crlsign" -> bits |= KeyUsage.cRLSign;
                case "encipheronly" -> bits |= KeyUsage.encipherOnly;
                case "decipheronly" -> bits |= KeyUsage.decipherOnly;
                default -> {
                    if (bits == 0) {
                        bits = KeyUsage.digitalSignature | KeyUsage.keyEncipherment;
                    }
                }
            }
        }
        return bits == 0 ? KeyUsage.digitalSignature | KeyUsage.keyEncipherment : bits;
    }

    private ExtendedKeyUsage buildExtendedKeyUsage(List<String> oids) {
        List<KeyPurposeId> purposes = new java.util.ArrayList<>();
        for (String oid : oids) {
            if (oid == null || oid.isBlank()) {
                continue;
            }
            String normalized = oid.trim();
            purposes.add(switch (normalized.toLowerCase()) {
                case "clientauth" -> KeyPurposeId.id_kp_clientAuth;
                case "serverauth" -> KeyPurposeId.id_kp_serverAuth;
                case "codesigning" -> KeyPurposeId.id_kp_codeSigning;
                case "emailprotection" -> KeyPurposeId.id_kp_emailProtection;
                case "timestamping" -> KeyPurposeId.id_kp_timeStamping;
                case "ocspsigning" -> KeyPurposeId.id_kp_OCSPSigning;
                default -> KeyPurposeId.getInstance(new ASN1ObjectIdentifier(normalized));
            });
        }
        return new ExtendedKeyUsage(purposes.toArray(new KeyPurposeId[0]));
    }

    private ASN1Encodable toAsn1Value(CustomExtension ext) {
        String type = ext.getType() == null ? "STRING" : ext.getType().trim().toUpperCase();
        String value = ext.getValue() == null ? "" : ext.getValue();
        return switch (type) {
            case "INTEGER" -> new ASN1Integer(new BigInteger(value.trim()));
            case "BOOLEAN" -> ASN1Boolean.getInstance(Boolean.parseBoolean(value.trim()));
            case "OCTETS" -> new DEROctetString(Base64.getDecoder().decode(value.trim()));
            default -> new DERUTF8String(value);
        };
    }

    public X509CertificateHolder parseCertificate(String certPem) {
        try (PEMParser parser = new PEMParser(new StringReader(normalizePem(certPem)))) {
            Object obj = parser.readObject();
            if (obj instanceof X509CertificateHolder holder) {
                return holder;
            }
            if (obj instanceof X509Certificate jcert) {
                return new X509CertificateHolder(jcert.getEncoded());
            }
            throw new BusinessException("PEM does not contain a certificate");
        } catch (Exception e) {
            throw new BusinessException("Unable to parse certificate: " + e.getMessage(), e);
        }
    }

    public X509Certificate parseJcaCertificate(String certPem) {
        try {
            return (X509Certificate) new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(parseCertificate(certPem));
        } catch (Exception e) {
            throw new BusinessException("Unable to parse certificate: " + e.getMessage(), e);
        }
    }

    public PrivateKey parsePrivateKey(String keyPem) {
        try (PEMParser parser = new PEMParser(new StringReader(normalizePem(keyPem)))) {
            Object obj = parser.readObject();
            if (obj instanceof org.bouncycastle.openssl.PEMKeyPair keyPair) {
                return BouncyCastleProvider.getPrivateKey(keyPair.getPrivateKeyInfo());
            }
            if (obj instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo pki) {
                return BouncyCastleProvider.getPrivateKey(pki);
            }
            if (obj instanceof org.bouncycastle.asn1.pkcs.RSAPrivateKey rsaKey) {
                // traditional PKCS#1 RSA PRIVATE KEY
                org.bouncycastle.asn1.x509.AlgorithmIdentifier algId =
                        new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                                org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.rsaEncryption,
                                org.bouncycastle.asn1.DERNull.INSTANCE);
                org.bouncycastle.asn1.pkcs.PrivateKeyInfo pki =
                        new org.bouncycastle.asn1.pkcs.PrivateKeyInfo(algId, rsaKey);
                return BouncyCastleProvider.getPrivateKey(pki);
            }
            if (obj instanceof org.bouncycastle.asn1.sec.ECPrivateKey sec1Key) {
                // traditional SEC1 EC PRIVATE KEY; restore the curve parameters
                org.bouncycastle.asn1.ASN1Object params = sec1Key.getParameters();
                if (params == null) {
                    throw new BusinessException("PEM EC private key is missing curve parameters");
                }
                org.bouncycastle.asn1.x9.X962Parameters x962 =
                        org.bouncycastle.asn1.x9.X962Parameters.getInstance(params);
                org.bouncycastle.asn1.x509.AlgorithmIdentifier algId =
                        new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                                org.bouncycastle.asn1.x9.X9ObjectIdentifiers.id_ecPublicKey, x962);
                org.bouncycastle.asn1.pkcs.PrivateKeyInfo pki =
                        new org.bouncycastle.asn1.pkcs.PrivateKeyInfo(algId, sec1Key);
                return BouncyCastleProvider.getPrivateKey(pki);
            }
            if (obj instanceof KeyPair kp) {
                return kp.getPrivate();
            }
            if (obj instanceof PrivateKey pk) {
                return pk;
            }
            throw new BusinessException("PEM does not contain a private key");
        } catch (IOException e) {
            throw new BusinessException("Unable to parse private key: " + e.getMessage(), e);
        }
    }

    public String toPrivateKeyPem(PrivateKey key) {
        try {
            // Write a standard PKCS#8 "PRIVATE KEY" PEM. JcaPEMWriter converts EC
            // PrivateKeyInfo to SEC1 "EC PRIVATE KEY" without curve parameters,
            // which cannot be parsed back, so the PKCS#8 DER is encoded directly.
            org.bouncycastle.asn1.pkcs.PrivateKeyInfo pki =
                    org.bouncycastle.asn1.pkcs.PrivateKeyInfo.getInstance(key.getEncoded());
            return "-----BEGIN PRIVATE KEY-----\n"
                    + java.util.Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(pki.getEncoded())
                    + "\n-----END PRIVATE KEY-----\n";
        } catch (Exception e) {
            throw new BusinessException("Private key PEM encoding failed: " + e.getMessage(), e);
        }
    }

    public String toPublicKeyPem(PublicKey key) {
        try {
            org.bouncycastle.asn1.x509.SubjectPublicKeyInfo spki =
                    org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(key.getEncoded());
            return toPem(spki);
        } catch (Exception e) {
            throw new BusinessException("Public key PEM encoding failed: " + e.getMessage(), e);
        }
    }

    public String toPem(Object obj) {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(sw)) {
            writer.writeObject(obj);
        } catch (IOException e) {
            throw new BusinessException("PEM encoding failed: " + e.getMessage(), e);
        }
        return sw.toString();
    }

    public String keyAlgorithmFor(PublicKey pubKey) {
        String alg = pubKey == null ? "" : pubKey.getAlgorithm();
        if (alg != null && (alg.equalsIgnoreCase("Ed25519") || alg.equalsIgnoreCase("Ed448")
                || alg.equalsIgnoreCase("EdDSA"))) {
            return edAlgorithmFor(pubKey);
        }
        return alg != null && alg.equalsIgnoreCase("EC") ? EC : RSA;
    }

    private String edAlgorithmFor(PublicKey pubKey) {
        // Sun reports both curves as "EdDSA"; the Ed448 OID (1.3.101.113)
        // distinguishes it from Ed25519 (1.3.101.112).
        try {
            org.bouncycastle.asn1.x509.SubjectPublicKeyInfo spki =
                    org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(pubKey.getEncoded());
            String oid = spki.getAlgorithm().getAlgorithm().getId();
            if ("1.3.101.113".equals(oid)) {
                return ED448;
            }
        } catch (Exception ignored) {
            // fall through to the Ed25519 default below
        }
        return ED25519;
    }

    public int keySizeFor(PublicKey pubKey) {
        if (pubKey instanceof RSAPublicKey rsa) {
            return rsa.getModulus().bitLength();
        }
        if (pubKey instanceof ECPublicKey ec) {
            return ec.getParams().getCurve().getField().getFieldSize();
        }
        if (pubKey != null) {
            String alg = pubKey.getAlgorithm();
            if (alg != null && (alg.equalsIgnoreCase("Ed25519") || alg.equalsIgnoreCase("Ed448")
                    || alg.equalsIgnoreCase("EdDSA"))) {
                return ED448.equals(edAlgorithmFor(pubKey)) ? 456 : 256;
            }
        }
        return 256;
    }

    public String normalizePem(String pem) {
        return pem == null ? "" : pem.trim();
    }

    public LocalDateTime now() {
        return LocalDateTime.ofInstant(Instant.now(), ZoneOffset.UTC);
    }
}
