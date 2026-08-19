package com.example.cm.service;

import com.example.cm.exception.BusinessException;
import com.example.cm.model.entity.CaEntity;
import com.example.cm.model.entity.CertificateEntity;
import com.example.cm.model.entity.CrlEntity;
import com.example.cm.model.enums.CertificateStatus;
import com.example.cm.model.enums.RevocationReason;
import com.example.cm.repository.CaRepository;
import com.example.cm.repository.CertificateRepository;
import com.example.cm.repository.CrlRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
@Service
@RequiredArgsConstructor
public class CrlService {

    private final CrlRepository crlRepository;
    private final CaRepository caRepository;
    private final CertificateRepository certificateRepository;
    private final CryptoService cryptoService;
    private final CaKeyService caKeyService;
    private final AuditService auditService;

    private final AtomicLong crlNumberGenerator = new AtomicLong(1);

    @Value("${cm.crl.validity-days:30}")
    private int crlValidityDays;

    @Transactional
    public CrlEntity generateCrl(Long caId) {
        CaEntity ca = caRepository.findById(caId)
                .orElseThrow(() -> new BusinessException("CA not found: " + caId));
        if (ca.getStatus() != CertificateStatus.ISSUED) {
            throw new BusinessException("Cannot generate CRL: CA is not active");
        }

        X509CertificateHolder issuerHolder = cryptoService.parseCertificate(ca.getCertificatePem());
        var caSigningKey = caKeyService.signingKey(ca);
        PrivateKey caKey = caSigningKey.key();
        X500Name issuerName = issuerHolder.getSubject();

        List<CertificateEntity> revokedCerts = certificateRepository
                .findByIssuerCaIdAndStatusIn(caId, List.of(CertificateStatus.REVOKED, CertificateStatus.SUSPENDED));

        LocalDateTime thisUpdate = LocalDateTime.now(ZoneOffset.UTC);
        LocalDateTime nextUpdate = thisUpdate.plusDays(crlValidityDays);

        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuerName, Date.from(thisUpdate.toInstant(ZoneOffset.UTC)));
        crlBuilder.setNextUpdate(Date.from(nextUpdate.toInstant(ZoneOffset.UTC)));

        for (CertificateEntity cert : revokedCerts) {
            RevocationReason reason = cert.getRevocationReason() != null
                    ? RevocationReason.valueOf(cert.getRevocationReason())
                    : RevocationReason.UNSPECIFIED;
            LocalDateTime when = cert.getRevokedAt() != null ? cert.getRevokedAt()
                    : cert.getSuspendedAt() != null ? cert.getSuspendedAt() : thisUpdate;
            if (reason == RevocationReason.REMOVE_FROM_CRL) {
                continue;
            }
            crlBuilder.addCRLEntry(new BigInteger(cert.getSerialNumber(), 16),
                    Date.from(when.toInstant(ZoneOffset.UTC)),
                    reasonToCode(reason));
        }

        long crlNumber = crlNumberGenerator.getAndIncrement();
        try {
            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            crlBuilder.addExtension(Extension.cRLNumber, false,
                    new CRLNumber(BigInteger.valueOf(crlNumber)));
            crlBuilder.addExtension(Extension.authorityKeyIdentifier, false,
                    extUtils.createAuthorityKeyIdentifier(issuerHolder));

            ContentSigner signer = new JcaContentSignerBuilder(ca.getSignatureAlgorithm())
                    .setProvider(caSigningKey.signerProvider() == null
                            ? BouncyCastleProvider.PROVIDER_NAME : caSigningKey.signerProvider())
                    .build(caKey);
            X509CRLHolder crlHolder = crlBuilder.build(signer);
            String crlPem = cryptoService.toPem(crlHolder);

            // mark previous CRL for this CA as superseded
            crlRepository.findTopByCaIdAndCurrentTrueOrderByIdDesc(caId)
                    .ifPresent(old -> {
                        old.setCurrent(false);
                        crlRepository.save(old);
                    });

            CrlEntity crl = CrlEntity.builder()
                    .caId(caId)
                    .caName(ca.getName())
                    .crlNumber(crlNumber)
                    .thisUpdate(thisUpdate)
                    .nextUpdate(nextUpdate)
                    .crlPem(crlPem)
                    .current(true)
                    .build();
            final List<String> revokedSerials = crl.getRevokedSerials();
            revokedCerts.forEach(c -> revokedSerials.add(c.getSerialNumber().toUpperCase()));
            crl = crlRepository.save(crl);

            // keep the last 10 CRLs per CA, drop older ones
            List<CrlEntity> history = crlRepository.findByCaIdOrderByIdDesc(caId);
            if (history.size() > 10) {
                history.subList(10, history.size()).forEach(old -> crlRepository.delete(old));
            }
            auditService.record(AuditService.currentActor(), "CRL", "CRL_GENERATED",
                    "ca=" + ca.getName() + ", crlNumber=" + crlNumber + ", revoked=" + revokedCerts.size());
            log.info("Generated CRL #{} for CA '{}' with {} revoked/suspended entries",
                    crlNumber, ca.getName(), revokedCerts.size());
            return crl;
        } catch (Exception e) {
            throw new BusinessException("CRL generation failed: " + e.getMessage(), e);
        }
    }

    @Transactional(readOnly = true)
    public CrlEntity getCurrentCrl(Long caId) {
        return crlRepository.findTopByCaIdAndCurrentTrueOrderByIdDesc(caId)
                .orElseThrow(() -> new BusinessException("No CRL available for CA " + caId + " yet"));
    }

    @Transactional(readOnly = true)
    public List<CrlEntity> getCrlHistory(Long caId) {
        return crlRepository.findByCaIdOrderByIdDesc(caId);
    }

    @Transactional(readOnly = true)
    public byte[] getCurrentCrlDer(Long caId) {
        return toDer(getCurrentCrl(caId).getCrlPem());
    }

    public byte[] toDer(String pem) {
        try {
            X509CRLHolder holder = derFromPem(pem);
            return holder.getEncoded();
        } catch (Exception e) {
            throw new BusinessException("CRL DER conversion failed: " + e.getMessage(), e);
        }
    }

    private X509CRLHolder derFromPem(String pem) throws Exception {
        try (java.io.StringReader sr = new java.io.StringReader(pem);
             org.bouncycastle.openssl.PEMParser parser = new org.bouncycastle.openssl.PEMParser(sr)) {
            Object obj = parser.readObject();
            if (obj instanceof X509CRLHolder holder) {
                return holder;
            }
            throw new BusinessException("PEM does not contain a CRL");
        }
    }

    private int reasonToCode(RevocationReason reason) {
        return switch (reason) {
            case KEY_COMPROMISE -> CRLReason.keyCompromise;
            case CA_COMPROMISE -> CRLReason.cACompromise;
            case AFFILIATION_CHANGED -> CRLReason.affiliationChanged;
            case SUPERSEDED -> CRLReason.superseded;
            case CESSATION_OF_OPERATION -> CRLReason.cessationOfOperation;
            case CERTIFICATE_HOLD -> CRLReason.certificateHold;
            case REMOVE_FROM_CRL -> CRLReason.removeFromCRL;
            case PRIVILEGE_WITHDRAWN -> CRLReason.privilegeWithdrawn;
            case AA_COMPROMISE -> CRLReason.aACompromise;
            default -> CRLReason.unspecified;
        };
    }

    @Scheduled(cron = "${cm.crl.refresh-cron:0 0 2 * * *}")
    public void refreshCrls() {
        log.info("Scheduled CRL refresh started");
        caRepository.findAll().stream()
                .filter(ca -> ca.getStatus() == CertificateStatus.ISSUED)
                .forEach(ca -> {
                    try {
                        generateCrl(ca.getId());
                    } catch (Exception e) {
                        log.error("Scheduled CRL refresh failed for CA {}", ca.getName(), e);
                    }
                });
    }
}
