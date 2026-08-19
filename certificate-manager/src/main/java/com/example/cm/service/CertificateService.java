package com.example.cm.service;

import com.example.cm.exception.BusinessException;
import com.example.cm.model.dto.CsrRequest;
import com.example.cm.model.dto.ManualCertificateRequest;
import com.example.cm.model.dto.RevokeRequest;
import com.example.cm.model.entity.CaEntity;
import com.example.cm.model.entity.CertificateEntity;
import com.example.cm.model.entity.CertificateProfile;
import com.example.cm.model.entity.CustomExtension;
import com.example.cm.model.entity.Pkcs11Settings;
import com.example.cm.model.enums.CertificateStatus;
import com.example.cm.model.enums.KeyStorage;
import com.example.cm.model.enums.RevocationReason;
import com.example.cm.repository.CertificateRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class CertificateService {

    private final CertificateRepository certificateRepository;
    private final CaService caService;
    private final CryptoService cryptoService;
    private final CrlService crlService;
    private final CaKeyService caKeyService;
    private final ProfileService profileService;
    private final Pkcs11Service pkcs11Service;
    private final AuditService auditService;

    @Value("${cm.cert.default-validity-days:365}")
    private int defaultValidityDays;

    @Transactional
    public CertificateEntity submitCsr(CsrRequest request) {
        PKCS10CertificationRequest csr = cryptoService.parseCsr(request.getCsrPem());
        int validityDays = defaultValidityDays;
        return registerCertificate(request.getRequestedBy(), request.getCsrPem(), null,
                request.getIssuerCaId(), validityDays, null, csr);
    }

    @Transactional
    public CertificateEntity requestCertificate(ManualCertificateRequest request, boolean adminUser) {
        CertificateProfile profile = null;
        if (request.getProfileId() != null) {
            profile = profileService.get(request.getProfileId());
            if (profile.isCaProfile() && !adminUser) {
                throw new BusinessException("CA certificate profiles can only be used by administrators");
            }
        }

        String algorithm = normalizeKeyAlgorithm(firstNonBlank(request.getKeyAlgorithm(),
                profile != null ? profile.getKeyAlgorithm() : null));
        int keySize = cryptoService.resolveKeySize(algorithm,
                request.getKeySize() != null && request.getKeySize() > 0
                        ? request.getKeySize()
                        : (profile != null ? profile.getKeySize() : null));

        Integer reqDays = request.getValidityDays();
        Integer reqMinutes = request.getValidityMinutes();
        Integer pDays = profile != null ? profile.getValidityDays() : null;
        Integer pMinutes = profile != null ? profile.getValidityMinutes() : null;

        Integer effectiveDays = null;
        Integer effectiveMinutes = null;
        if (reqMinutes != null) {
            effectiveMinutes = Math.min(Math.max(reqMinutes, 1), 525600);
        } else if (reqDays != null) {
            effectiveDays = Math.min(Math.max(reqDays, 1), 3650);
        } else if (pMinutes != null) {
            effectiveMinutes = Math.min(Math.max(pMinutes, 1), 525600);
        } else if (pDays != null) {
            effectiveDays = Math.min(Math.max(pDays, 1), 3650);
        } else {
            effectiveDays = defaultValidityDays;
        }
        long validitySeconds = effectiveMinutes != null
                ? effectiveMinutes * 60L : effectiveDays * 86400L;
        int validityDays = (int) Math.max(1, Math.ceil(validitySeconds / 86400.0));

        X500Name subject = buildSubject(request);
        List<GeneralName> sanNames = buildSubjectAltNames(request);

        KeyStorage keyStorage = resolveKeyStorage(profile);
        String pkcs11Alias = null;
        String privateKeyPem = null;
        PKCS10CertificationRequest csr;
        if (keyStorage == KeyStorage.PKCS11) {
            ensurePkcs11Configured();
            pkcs11Alias = buildPkcs11Alias(request.getCommonName());
            // The pending record only carries the request intent (subject/SANs).
            // The real token-resident key pair is generated at issuance time so the
            // key + certificate are stored on the device atomically (mirrors the CA flow).
            KeyPair placeholderKeys = cryptoService.generateKeyPair(algorithm, keySize);
            csr = cryptoService.buildCsr(subject, sanNames, placeholderKeys,
                    cryptoService.signatureAlgorithmFor(algorithm, keySize));
        } else {
            KeyPair keyPair = cryptoService.generateKeyPair(algorithm, keySize);
            csr = cryptoService.buildCsr(subject, sanNames, keyPair,
                    cryptoService.signatureAlgorithmFor(algorithm, keySize));
            privateKeyPem = cryptoService.toPrivateKeyPem(keyPair.getPrivate());
        }
        String csrPem = cryptoService.toPem(csr);

        List<String> keyUsage = profile != null && profile.getKeyUsage() != null
                ? profile.getKeyUsage() : List.of();
        List<String> eku = profile != null && profile.getExtendedKeyUsage() != null
                ? profile.getExtendedKeyUsage() : List.of();
        List<CustomExtension> customExt = new ArrayList<>();
        if (profile != null && profile.getAdditionalExtensions() != null) {
            customExt.addAll(profile.getAdditionalExtensions());
        }
        if (request.getAdditionalExtensions() != null) {
            customExt.addAll(request.getAdditionalExtensions());
        }

        return registerCertificate(request.getRequestedBy(), csrPem, privateKeyPem,
                request.getIssuerCaId(), validityDays, effectiveMinutes, csr,
                profile != null ? profile.getName() : null,
                profile != null && profile.isCaProfile(),
                keyUsage, eku, customExt, keyStorage, pkcs11Alias);
    }

    private String firstNonBlank(String primary, String fallback) {
        return primary != null && !primary.isBlank() ? primary : fallback;
    }

    private CertificateEntity registerCertificate(String requestedBy, String csrPem, String privateKeyPem,
                                                  Long issuerCaId, int validityDays, Integer validityMinutes,
                                                  PKCS10CertificationRequest csr) {
        return registerCertificate(requestedBy, csrPem, privateKeyPem, issuerCaId, validityDays,
                validityMinutes, csr, null, false, List.of(), List.of(), List.of(),
                KeyStorage.DATABASE, null);
    }

    private CertificateEntity registerCertificate(String requestedBy, String csrPem, String privateKeyPem,
                                                  Long issuerCaId, int validityDays, Integer validityMinutes,
                                                  PKCS10CertificationRequest csr, String profileName,
                                                  boolean caProfile, List<String> keyUsage,
                                                  List<String> eku, List<CustomExtension> customExt,
                                                  KeyStorage keyStorage, String pkcs11Alias) {
        CaEntity issuer = resolveIssuer(issuerCaId);

        PublicKey pubKey = cryptoService.extractPublicKey(csr);
        String subjectDn = cryptoService.subjectDnFromCsr(csr);
        String commonName = cryptoService.commonNameFromCsr(csr);

        CertificateEntity cert = CertificateEntity.builder()
                .commonName(commonName)
                .subjectDn(subjectDn)
                .status(CertificateStatus.PENDING)
                .csrPem(csrPem)
                .privateKeyPem(privateKeyPem)
                .keyStorage(keyStorage)
                .pkcs11Alias(pkcs11Alias)
                .publicKeyPem(cryptoService.toPublicKeyPem(pubKey))
                .keyAlgorithm(cryptoService.keyAlgorithmFor(pubKey))
                .keySize(cryptoService.keySizeFor(pubKey))
                .validityDays(validityDays)
                .validityMinutes(validityMinutes)
                .issuerCaId(issuer.getId())
                .requestedBy(requestedBy)
                .createdAt(LocalDateTime.now())
                .profileName(profileName)
                .caProfile(caProfile)
                .keyUsage(new ArrayList<>(keyUsage))
                .extendedKeyUsage(new ArrayList<>(eku))
                .additionalExtensions(new ArrayList<>(customExt))
                .build();
        cert = certificateRepository.save(cert);

        issue(cert, requestedBy);
        auditService.record(AuditService.currentActor(), "CERT", "CERT_ISSUED",
                "cn=" + commonName + ", serial=" + cert.getSerialNumber() + ", issuer=" + issuer.getName()
                        + (profileName != null ? ", profile=" + profileName : ""));
        log.info("Certificate '{}' issued by CA '{}'", commonName, issuer.getName());
        return cert;
    }

    private KeyStorage resolveKeyStorage(CertificateProfile profile) {
        if (profile != null && profile.getKeyStorage() != null) {
            return profile.getKeyStorage();
        }
        return KeyStorage.DATABASE;
    }

    private void ensurePkcs11Configured() {
        Pkcs11Settings settings = pkcs11Service.getSettings();
        if (!settings.isEnabled()
                || settings.getLibraryPath() == null || settings.getLibraryPath().isBlank()) {
            throw new BusinessException("PKCS#11 key storage requires the PKCS#11 device to be enabled "
                    + "and a library path configured in Settings > PKCS#11 device");
        }
    }

    private String buildPkcs11Alias(String commonName) {
        String slug = commonName == null ? "" : commonName.trim().toLowerCase()
                .replaceAll("[^a-z0-9]+", "-").replaceAll("^-|-$", "");
        if (slug.isBlank()) {
            slug = "cert";
        }
        return "cert-" + slug + "-" + Integer.toHexString(new SecureRandom().nextInt());
    }

    private List<GeneralName> sansFromCsr(PKCS10CertificationRequest csr) {
        GeneralNames names = cryptoService.sansFromCsr(csr);
        return names == null ? List.of() : List.of(names.getNames());
    }

    private CaEntity resolveIssuer(Long issuerCaId) {
        CaEntity issuer;
        if (issuerCaId != null) {
            issuer = caService.get(issuerCaId);
        } else {
            List<CaEntity> active = caService.listActive();
            if (active.isEmpty()) {
                throw new BusinessException("No active CA available to issue certificates");
            }
            issuer = active.get(0);
        }
        if (issuer.getStatus() != CertificateStatus.ISSUED) {
            throw new BusinessException("Issuer CA '" + issuer.getName() + "' is not active");
        }
        return issuer;
    }

    private String normalizeKeyAlgorithm(String algorithm) {
        return cryptoService.normalizeKeyAlgorithm(algorithm);
    }

    private X500Name buildSubject(ManualCertificateRequest request) {
        X500NameBuilder builder = new X500NameBuilder(X500Name.getDefaultStyle());
        String country = isNotBlank(request.getCountry()) ? request.getCountry().trim() : null;
        if (country != null && !country.matches("[A-Za-z]{2}")) {
            throw new BusinessException("Country must be a 2-letter code");
        }
        if (country != null) builder.addRDN(BCStyle.C, country.toUpperCase());
        if (isNotBlank(request.getState())) builder.addRDN(BCStyle.ST, request.getState().trim());
        if (isNotBlank(request.getLocality())) builder.addRDN(BCStyle.L, request.getLocality().trim());
        if (isNotBlank(request.getOrganization())) builder.addRDN(BCStyle.O, request.getOrganization().trim());
        if (isNotBlank(request.getOrganizationalUnit())) builder.addRDN(BCStyle.OU, request.getOrganizationalUnit().trim());
        if (isNotBlank(request.getEmailAddress())) builder.addRDN(BCStyle.EmailAddress, request.getEmailAddress().trim());
        builder.addRDN(BCStyle.CN, request.getCommonName().trim());
        return builder.build();
    }

    private List<GeneralName> buildSubjectAltNames(ManualCertificateRequest request) {
        List<GeneralName> names = new ArrayList<>();
        if (request.getDnsNames() != null) {
            for (String dns : request.getDnsNames()) {
                if (isNotBlank(dns)) names.add(new GeneralName(GeneralName.dNSName, dns.trim()));
            }
        }
        if (request.getIpAddresses() != null) {
            for (String ip : request.getIpAddresses()) {
                if (isNotBlank(ip)) names.add(new GeneralName(GeneralName.iPAddress, ip.trim()));
            }
        }
        if (names.isEmpty() && isNotBlank(request.getCommonName())) {
            String cn = request.getCommonName().trim();
            if (cn.matches("[0-9]+(\\.[0-9]+){3}")) {
                names.add(new GeneralName(GeneralName.iPAddress, cn));
            } else {
                names.add(new GeneralName(GeneralName.dNSName, cn));
            }
        }
        return names;
    }

    private boolean isNotBlank(String s) {
        return s != null && !s.isBlank();
    }

    private void issue(CertificateEntity cert, String requestedBy) {
        try {
            CaEntity issuer = caService.get(cert.getIssuerCaId());
            var issuerHolder = cryptoService.parseCertificate(issuer.getCertificatePem());
            var issuerSigningKey = caKeyService.signingKey(issuer);
            PKCS10CertificationRequest csr = cryptoService.parseCsr(cert.getCsrPem());
            PublicKey pubKey = cryptoService.extractPublicKey(csr);

            KeyPair tokenKeys = null;
            if (cert.getKeyStorage() == KeyStorage.PKCS11) {
                if (cert.getPkcs11Alias() == null || cert.getPkcs11Alias().isBlank()) {
                    throw new BusinessException("Certificate is PKCS#11-backed but has no token alias");
                }
                String tokenProvider = pkcs11Service.providerName();
                tokenKeys = pkcs11Service.generateKeyPair(cert.getPkcs11Alias(),
                        cert.getKeyAlgorithm(), cert.getKeySize());
                // Rebuild the CSR on the token public key so the issued certificate
                // matches the device-resident private key (subject/SANs are kept).
                X500Name subject = cryptoService.subjectFromCsr(csr);
                List<GeneralName> sans = sansFromCsr(csr);
                csr = cryptoService.buildCsr(subject, sans, tokenKeys,
                        cryptoService.signatureAlgorithmFor(cert.getKeyAlgorithm(), cert.getKeySize()), tokenProvider);
                pubKey = cryptoService.extractPublicKey(csr);
                cert.setCsrPem(cryptoService.toPem(csr));
                cert.setPublicKeyPem(cryptoService.toPublicKeyPem(pubKey));
            }

            long validitySeconds = cert.getValidityMinutes() != null
                    ? cert.getValidityMinutes() * 60L
                    : (cert.getValidityDays() != null ? cert.getValidityDays() : defaultValidityDays) * 86400L;
            String certPem = cryptoService.buildSignedCertificate(
                    issuerHolder, issuerSigningKey.key(), issuer.getSignatureAlgorithm(),
                    csr, pubKey, validitySeconds, cert.isCaProfile(),
                    cert.getKeyUsage() != null ? cert.getKeyUsage() : List.of(),
                    cert.getExtendedKeyUsage() != null ? cert.getExtendedKeyUsage() : List.of(),
                    cert.getAdditionalExtensions() != null ? cert.getAdditionalExtensions() : List.of(),
                    issuerSigningKey.signerProvider());

            if (tokenKeys != null) {
                pkcs11Service.storeKeyAndCertificate(cert.getPkcs11Alias(), tokenKeys.getPrivate(),
                        cryptoService.parseJcaCertificate(certPem));
            }

            LocalDateTime now = LocalDateTime.now();
            cert.setCertificatePem(certPem);
            cert.setSerialNumber(cryptoService.parseCertificate(certPem).getSerialNumber().toString(16).toUpperCase());
            cert.setSignatureAlgorithm(issuer.getSignatureAlgorithm());
            cert.setValidFrom(now);
            cert.setValidTo(now.plusSeconds(validitySeconds));
            cert.setStatus(CertificateStatus.ISSUED);
            cert.setApproverName(requestedBy);
            cert.setIssuedAt(now);
            certificateRepository.save(cert);
            log.info("Certificate '{}' issued by CA '{}'", cert.getCommonName(), issuer.getName());
        } catch (BusinessException e) {
            cert.setStatus(CertificateStatus.REJECTED);
            certificateRepository.save(cert);
            throw e;
        } catch (Exception e) {
            cert.setStatus(CertificateStatus.REJECTED);
            certificateRepository.save(cert);
            throw new BusinessException("Certificate issuance failed: " + e.getMessage(), e);
        }
    }

    @Transactional
    public CertificateEntity revoke(Long id, RevokeRequest request) {
        CertificateEntity cert = get(id);
        if (cert.getStatus() != CertificateStatus.ISSUED && cert.getStatus() != CertificateStatus.SUSPENDED) {
            throw new BusinessException("Only issued or suspended certificates can be revoked");
        }
        RevocationReason reason = request.getReason() != null ? request.getReason() : RevocationReason.UNSPECIFIED;
        cert.setStatus(CertificateStatus.REVOKED);
        cert.setRevokedAt(LocalDateTime.now());
        cert.setRevocationReason(reason.name());
        certificateRepository.save(cert);
        auditService.record(AuditService.currentActor(), "CERT", "CERT_REVOKED",
                "cn=" + cert.getCommonName() + ", serial=" + cert.getSerialNumber() + ", reason=" + reason);
        refreshCrl(cert.getIssuerCaId());
        return cert;
    }

    @Transactional
    public CertificateEntity suspend(Long id) {
        CertificateEntity cert = get(id);
        if (cert.getStatus() != CertificateStatus.ISSUED) {
            throw new BusinessException("Only issued certificates can be suspended");
        }
        cert.setStatus(CertificateStatus.SUSPENDED);
        cert.setSuspendedAt(LocalDateTime.now());
        cert.setRevocationReason(RevocationReason.CERTIFICATE_HOLD.name());
        certificateRepository.save(cert);
        auditService.record(AuditService.currentActor(), "CERT", "CERT_SUSPENDED",
                "cn=" + cert.getCommonName() + ", serial=" + cert.getSerialNumber());
        refreshCrl(cert.getIssuerCaId());
        return cert;
    }

    @Transactional
    public CertificateEntity resume(Long id) {
        CertificateEntity cert = get(id);
        if (cert.getStatus() != CertificateStatus.SUSPENDED) {
            throw new BusinessException("Only suspended certificates can be resumed");
        }
        cert.setStatus(CertificateStatus.ISSUED);
        cert.setSuspendedAt(null);
        cert.setRevocationReason(null);
        certificateRepository.save(cert);
        auditService.record(AuditService.currentActor(), "CERT", "CERT_RESUMED",
                "cn=" + cert.getCommonName() + ", serial=" + cert.getSerialNumber());
        refreshCrl(cert.getIssuerCaId());
        return cert;
    }

    private void refreshCrl(Long issuerCaId) {
        if (issuerCaId != null) {
            try {
                crlService.generateCrl(issuerCaId);
            } catch (Exception e) {
                log.warn("CRL refresh failed: {}", e.getMessage());
            }
        }
    }

    @Transactional(readOnly = true)
    public CertificateEntity get(Long id) {
        return certificateRepository.findById(id)
                .orElseThrow(() -> new BusinessException("Certificate not found: " + id));
    }

    @Transactional(readOnly = true)
    public Optional<CertificateEntity> findBySerial(String serialHex) {
        if (serialHex == null || serialHex.isBlank()) {
            return Optional.empty();
        }
        try {
            return certificateRepository.findBySerialNumber(serialHex.trim().toUpperCase());
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    @Transactional(readOnly = true)
    public List<CertificateEntity> listAll() {
        return certificateRepository.findAll();
    }

    /**
     * Case-insensitive search across all certificates and certificate requests
     * (common name, subject DN, serial number, requester) with optional status and
     * CA filters. Available to every authenticated role: admins and requesters can
     * both search and view any certificate.
     */
    @Transactional(readOnly = true)
    public List<CertificateEntity> search(String q, CertificateStatus status, Long caId) {
        String pattern = (q == null || q.isBlank()) ? null : "%" + q.trim().toLowerCase() + "%";
        return certificateRepository.search(pattern, status, caId);
    }

    @Transactional(readOnly = true)
    public List<CertificateEntity> listByStatus(CertificateStatus status) {
        return certificateRepository.findByStatus(status);
    }

    @Transactional(readOnly = true)
    public List<CertificateEntity> listByCa(Long caId) {
        return certificateRepository.findByIssuerCaId(caId);
    }
}
