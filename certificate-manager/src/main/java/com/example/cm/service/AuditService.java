package com.example.cm.service;

import com.example.cm.exception.BusinessException;
import com.example.cm.model.dto.AuditVerificationResult;
import com.example.cm.model.entity.AuditKeyEntity;
import com.example.cm.model.entity.AuditLog;
import com.example.cm.repository.AuditKeyRepository;
import com.example.cm.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;

/**
 * Tamper-evident signed audit log. Every recorded event is chained to the
 * previous one (SHA-256 hash) and signed with an HMAC-SHA256 secret that is
 * generated once and persisted, so the whole log can be verified end-to-end.
 */
@Service
@RequiredArgsConstructor
public class AuditService {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String HASH_ALGORITHM = "SHA-256";
    private static final long AUDIT_KEY_ID = 1L;

    private final AuditLogRepository auditLogRepository;
    private final AuditKeyRepository auditKeyRepository;

    private volatile byte[] hmacSecret;

    /**
     * Records a signed, chained audit entry. Runs in its own transaction so the
     * entry survives even when the surrounding business transaction rolls back.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public synchronized void record(String actor, String category, String action, String detail) {
        AuditLog prev = auditLogRepository.findTopByOrderByIdDesc().orElse(null);
        String prevHash = prev == null ? "" : prev.getHash();

        LocalDateTime ts = LocalDateTime.now();
        LocalDateTime timestamp = ts.withNano((ts.getNano() / 1_000_000) * 1_000_000);
        String payload = buildPayload(timestamp, actor, category, action, detail, prevHash);

        String hash = hex(sha256(payload));
        String signature = hex(hmac(secret(), payload));

        auditLogRepository.save(AuditLog.builder()
                .timestamp(timestamp)
                .actor(normalize(actor))
                .category(normalize(category))
                .action(normalize(action))
                .detail(normalize(detail))
                .prevHash(prevHash)
                .hash(hash)
                .signature(signature)
                .build());
    }

    /**
     * Recomputes the whole chain and checks every entry's hash, signature and
     * prevHash link.
     */
    @Transactional(readOnly = true)
    public AuditVerificationResult verify() {
        List<AuditLog> entries = auditLogRepository.findAllByOrderByIdAsc();
        String prevHash = "";
        long verified = 0;
        byte[] key = secret();
        for (AuditLog entry : entries) {
            String payload = buildPayload(entry.getTimestamp(), entry.getActor(), entry.getCategory(),
                    entry.getAction(), entry.getDetail(), entry.getPrevHash());
            String expectedHash = hex(sha256(payload));
            String expectedSignature = hex(hmac(key, payload));
            if (!entry.getPrevHash().equals(prevHash)
                    || !expectedHash.equals(entry.getHash())
                    || !expectedSignature.equals(entry.getSignature())) {
                return new AuditVerificationResult(false, entries.size(), verified,
                        entry.getId(), "Audit chain broken at entry #" + entry.getId());
            }
            prevHash = entry.getHash();
            verified++;
        }
        return new AuditVerificationResult(true, entries.size(), verified, null, "Audit chain is intact");
    }

    /** Resolves the acting user from the security context, defaulting to "system". */
    public static String currentActor() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && auth.getName() != null
                && !"anonymousUser".equals(auth.getName())) {
            return auth.getName();
        }
        return "system";
    }

    private byte[] secret() {
        byte[] cached = hmacSecret;
        if (cached != null) {
            return cached;
        }
        AuditKeyEntity row = auditKeyRepository.findById(AUDIT_KEY_ID).orElse(null);
        if (row == null || row.getHmacSecret() == null || row.getHmacSecret().isBlank()) {
            byte[] generated = new byte[32];
            new SecureRandom().nextBytes(generated);
            String encoded = Base64.getEncoder().encodeToString(generated);
            row = AuditKeyEntity.builder()
                    .id(AUDIT_KEY_ID)
                    .hmacSecret(encoded)
                    .createdAt(LocalDateTime.now())
                    .build();
            auditKeyRepository.save(row);
            hmacSecret = generated;
            return generated;
        }
        byte[] decoded = Base64.getDecoder().decode(row.getHmacSecret());
        hmacSecret = decoded;
        return decoded;
    }

    private String buildPayload(LocalDateTime timestamp, String actor, String category,
                                String action, String detail, String prevHash) {
        return timestamp + "|" + normalize(actor) + "|" + normalize(category)
                + "|" + normalize(action) + "|" + normalize(detail) + "|" + normalize(prevHash);
    }

    private String normalize(String value) {
        return value == null ? "" : value;
    }

    private byte[] hmac(byte[] key, String data) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
            return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new BusinessException("Unable to sign audit entry: " + e.getMessage(), e);
        }
    }

    private byte[] sha256(String data) {
        try {
            return MessageDigest.getInstance(HASH_ALGORITHM).digest(data.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new BusinessException("Unable to hash audit entry: " + e.getMessage(), e);
        }
    }

    private String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}
