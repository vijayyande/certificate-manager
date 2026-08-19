package com.example.cm.service;

import com.example.cm.model.entity.CaEntity;
import com.example.cm.model.enums.KeyStorage;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Storage-aware CA key handling. Depending on a CA's {@code keyStorage} either
 * the database-held key PEM or the PKCS#11 token key is used. The returned
 * {@link CaSigningKey#signerProvider()} is null for database keys (sign with
 * Bouncy Castle) and the SunPKCS11 provider name for token keys (sign natively
 * on the device).
 */
@Service
@RequiredArgsConstructor
public class CaKeyService {

    private final CryptoService cryptoService;
    private final Pkcs11Service pkcs11Service;

    public record CaSigningKey(PrivateKey key, String signerProvider) {
    }

    public record GeneratedCaKeys(KeyPair keyPair, PrivateKey privateKey, String signerProvider) {
    }

    public boolean isPkcs11(CaEntity ca) {
        return KeyStorage.PKCS11.equals(ca.getKeyStorage());
    }

    /** Resolve the CA's signing key (token-resident for PKCS#11, PEM otherwise). */
    public CaSigningKey signingKey(CaEntity ca) {
        if (isPkcs11(ca)) {
            if (ca.getPkcs11Alias() == null || ca.getPkcs11Alias().isBlank()) {
                throw new com.example.cm.exception.BusinessException(
                        "CA '" + ca.getName() + "' is PKCS#11-backed but has no token alias");
            }
            return new CaSigningKey(pkcs11Service.getPrivateKey(ca.getPkcs11Alias()),
                    pkcs11Service.providerName());
        }
        return new CaSigningKey(cryptoService.parsePrivateKey(ca.getPrivateKeyPem()), null);
    }

    /** Generate a CA key pair on the configured storage medium. */
    public GeneratedCaKeys generateCaKeys(CaEntity ca, String pkcs11Alias) {
        if (isPkcs11(ca)) {
            KeyPair keyPair = pkcs11Service.generateKeyPair(pkcs11Alias, ca.getKeyAlgorithm(), ca.getKeySize());
            return new GeneratedCaKeys(keyPair, keyPair.getPrivate(), pkcs11Service.providerName());
        }
        KeyPair keyPair = cryptoService.generateKeyPair(ca.getKeyAlgorithm(), ca.getKeySize());
        return new GeneratedCaKeys(keyPair, keyPair.getPrivate(), null);
    }

    /** Persist the issued CA certificate together with its key on the device. */
    public void storeCaCertificate(CaEntity ca, PrivateKey privateKey, X509Certificate certificate) {
        if (isPkcs11(ca)) {
            pkcs11Service.storeKeyAndCertificate(ca.getPkcs11Alias(), privateKey, certificate);
        }
    }
}
