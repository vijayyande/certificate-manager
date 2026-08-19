package com.example.cm.service;

import com.example.cm.exception.BusinessException;
import com.example.cm.model.entity.CaEntity;
import com.example.cm.model.entity.CertificateEntity;
import com.example.cm.model.enums.CertificateStatus;
import com.example.cm.model.enums.RevocationReason;
import com.example.cm.repository.CaRepository;
import com.example.cm.repository.CertificateRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class OcspService {

    private final CertificateRepository certificateRepository;
    private final CaRepository caRepository;
    private final CryptoService cryptoService;
    private final CaKeyService caKeyService;
    private final AuditService auditService;

    @Transactional(readOnly = true)
    public byte[] respond(byte[] ocspRequestDer) {
        try {
            OCSPReq ocspReq = new OCSPReq(ocspRequestDer);
            Req[] requestList = ocspReq.getRequestList();
            if (requestList.length == 0) {
                return errorResponse(OCSPRespBuilder.MALFORMED_REQUEST, "No OCSP request entries");
            }

            CertificateID certId = requestList[0].getCertID();
            BigInteger serial = certId.getSerialNumber();
            String serialHex = serial.toString(16).toUpperCase();
            log.info("OCSP request for serial {}", serialHex);

            Optional<CertificateEntity> optCert = certificateRepository.findBySerialNumber(serialHex);
            if (optCert.isEmpty()) {
                return errorResponse(OCSPRespBuilder.UNAUTHORIZED, "Certificate serial not found");
            }
            CertificateEntity cert = optCert.get();

            CaEntity issuer = caRepository.findById(cert.getIssuerCaId())
                    .orElseThrow(() -> new BusinessException("Issuer CA not found"));
            if (issuer.getStatus() != CertificateStatus.ISSUED) {
                return errorResponse(OCSPRespBuilder.UNAUTHORIZED, "Issuer CA not active");
            }

            X509Certificate issuerCert = new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(cryptoService.parseCertificate(issuer.getCertificatePem()));

            DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().build();
            CertificateID expectedId = new JcaCertificateID(digCalcProv.get(CertificateID.HASH_SHA1),
                    issuerCert, serial);
            if (!expectedId.equals(certId)) {
                return errorResponse(OCSPRespBuilder.UNAUTHORIZED, "CertID mismatch with issuer");
            }

            org.bouncycastle.cert.X509CertificateHolder issuerHolder =
                    cryptoService.parseCertificate(issuer.getCertificatePem());

            BasicOCSPRespBuilder basicBuilder = new BasicOCSPRespBuilder(
                    issuerHolder.getSubjectPublicKeyInfo(), digCalcProv.get(CertificateID.HASH_SHA1));

            org.bouncycastle.cert.ocsp.CertificateStatus status;
            Date revocationTime = null;
            int revocationReason = CRLReason.unspecified;

            switch (cert.getStatus()) {
                case REVOKED -> {
                    revocationTime = Date.from((cert.getRevokedAt() != null ? cert.getRevokedAt() : LocalDateTime.now())
                            .toInstant(ZoneOffset.UTC));
                    revocationReason = reasonToCrlReason(cert.getRevocationReason());
                    status = new RevokedStatus(revocationTime, revocationReason);
                }
                case SUSPENDED -> {
                    revocationTime = Date.from((cert.getSuspendedAt() != null ? cert.getSuspendedAt() : LocalDateTime.now())
                            .toInstant(ZoneOffset.UTC));
                    status = new RevokedStatus(revocationTime, CRLReason.certificateHold);
                }
                case ISSUED -> status = org.bouncycastle.cert.ocsp.CertificateStatus.GOOD;
                default -> status = new UnknownStatus();
            }

            // BC's CertificateStatus.GOOD is null; for issued certs we must pass a
            // null status (the responder fills in an empty good CertStatus). The
            // convenience overload computes thisUpdate = now and lets the
            // RevokedStatus carry its own revocation time/reason for revoked certs.
            basicBuilder.addResponse(certId, status);

            var caSigningKey = caKeyService.signingKey(issuer);
            BasicOCSPResp basicResp = basicBuilder.build(
                    new JcaContentSignerBuilder(issuer.getSignatureAlgorithm())
                            .setProvider(caSigningKey.signerProvider() == null
                                    ? BouncyCastleProvider.PROVIDER_NAME : caSigningKey.signerProvider())
                            .build(caSigningKey.key()),
                    new org.bouncycastle.cert.X509CertificateHolder[]{issuerHolder},
                    new Date());

            OCSPRespBuilder respBuilder = new OCSPRespBuilder();
            OCSPResp response = respBuilder.build(OCSPRespBuilder.SUCCESSFUL, basicResp);
            auditService.record("ocsp", "OCSP", "OCSP_RESPONSE",
                    "serial=" + serialHex + ", status=" + cert.getStatus());
            log.info("OCSP response for serial {} -> status {}", serial.toString(16), cert.getStatus());
            return response.getEncoded();
        } catch (Exception e) {
            log.error("OCSP processing failed", e);
            return errorResponse(OCSPRespBuilder.INTERNAL_ERROR, e.getMessage());
        }
    }

    @Transactional(readOnly = true)
    public String checkStatus(String serialHex) {
        Optional<CertificateEntity> optCert = certificateRepository.findBySerialNumber(
                serialHex.trim().toUpperCase());
        if (optCert.isEmpty()) {
            return "UNKNOWN";
        }
        return switch (optCert.get().getStatus()) {
            case ISSUED -> "GOOD";
            case SUSPENDED -> "REVOKED (certificateHold)";
            case REVOKED -> "REVOKED (" + optCert.get().getRevocationReason() + ")";
            default -> "UNKNOWN";
        };
    }

    private byte[] errorResponse(int responseStatus, String message) {
        try {
            log.warn("OCSP error: {}", message);
            OCSPRespBuilder builder = new OCSPRespBuilder();
            OCSPResp resp = builder.build(responseStatus, null);
            return resp.getEncoded();
        } catch (Exception e) {
            return new byte[0];
        }
    }

    private int reasonToCrlReason(String reasonName) {
        try {
            RevocationReason reason = reasonName != null ? RevocationReason.valueOf(reasonName) : RevocationReason.UNSPECIFIED;
            return switch (reason) {
                case KEY_COMPROMISE -> CRLReason.keyCompromise;
                case CA_COMPROMISE -> CRLReason.cACompromise;
                case AFFILIATION_CHANGED -> CRLReason.affiliationChanged;
                case SUPERSEDED -> CRLReason.superseded;
                case CESSATION_OF_OPERATION -> CRLReason.cessationOfOperation;
                case CERTIFICATE_HOLD -> CRLReason.certificateHold;
                case PRIVILEGE_WITHDRAWN -> CRLReason.privilegeWithdrawn;
                case AA_COMPROMISE -> CRLReason.aACompromise;
                default -> CRLReason.unspecified;
            };
        } catch (Exception e) {
            return CRLReason.unspecified;
        }
    }
}
