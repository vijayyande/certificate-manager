package com.example.cm.config;

import com.example.cm.model.entity.CaEntity;
import com.example.cm.model.entity.CertificateProfile;
import com.example.cm.model.entity.UserEntity;
import com.example.cm.model.enums.CaType;
import com.example.cm.model.enums.CertificateStatus;
import com.example.cm.model.enums.KeyStorage;
import com.example.cm.model.enums.ProfileType;
import com.example.cm.repository.CaRepository;
import com.example.cm.repository.CertificateProfileRepository;
import com.example.cm.repository.UserRepository;
import com.example.cm.service.AuditService;
import com.example.cm.service.CaService;
import com.example.cm.service.CryptoService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Bootstraps a demo root CA + intermediate CA and a set of default certificate
 * profiles when the database is empty, so the platform is usable immediately.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DataSeeder implements ApplicationRunner {

    private final CaRepository caRepository;
    private final CertificateProfileRepository profileRepository;
    private final UserRepository userRepository;
    private final CryptoService cryptoService;
    private final AuditService auditService;
    private final PasswordEncoder passwordEncoder;

    private static final String ROOT_DN = "CN=Demo Root CA, O=Certificate Manager, C=US";
    private static final String INTERMEDIATE_DN = "CN=Demo Intermediate CA, O=Certificate Manager, C=US";

    @Override
    public void run(ApplicationArguments args) {
        seedUsers();
        seedCAs();
        seedProfiles();
    }

    private void seedUsers() {
        if (userRepository.count() > 0) {
            return;
        }
        try {
            log.info("Seeding demo users...");
            LocalDateTime now = LocalDateTime.now();
            Set<String> adminRoles = new HashSet<>(Set.of("ADMIN", "REQUESTER"));
            Set<String> requesterRoles = new HashSet<>(Set.of("REQUESTER"));
            userRepository.save(UserEntity.builder()
                    .username("admin")
                    .password(passwordEncoder.encode("admin123"))
                    .roles(adminRoles)
                    .enabled(true)
                    .createdAt(now)
                    .updatedAt(now)
                    .build());
            userRepository.save(UserEntity.builder()
                    .username("requester")
                    .password(passwordEncoder.encode("requester123"))
                    .roles(requesterRoles)
                    .enabled(true)
                    .createdAt(now)
                    .updatedAt(now)
                    .build());
            auditService.record("system", "SEED", "SEED_USERS_CREATED", "admin, requester");
            log.info("Seeded 2 demo users");
        } catch (Exception e) {
            log.error("Failed to seed demo users: {}", e.getMessage(), e);
        }
    }

    private void seedCAs() {
        if (caRepository.count() > 0) {
            return;
        }
        try {
            log.info("Seeding demo CA hierarchy...");
            CaEntity root = createCa("Demo Root CA", ROOT_DN, CaType.ROOT, null);
            CaEntity intermediate = createCa("Demo Intermediate CA", INTERMEDIATE_DN,
                    CaType.INTERMEDIATE, root.getId());
            log.info("Seeded root CA '{}' (id={}) and intermediate CA '{}' (id={})",
                    root.getName(), root.getId(), intermediate.getName(), intermediate.getId());
            auditService.record("system", "SEED", "SEED_CA_CREATED",
                    "root=" + root.getName() + ", intermediate=" + intermediate.getName());
        } catch (Exception e) {
            log.error("Failed to seed demo CAs: {}", e.getMessage(), e);
        }
    }

    private void seedProfiles() {
        if (profileRepository.count() > 0) {
            return;
        }
        try {
            log.info("Seeding default certificate profiles...");
            createProfile("CA Certificate", ProfileType.CA);
            createProfile("SSL Certificate", ProfileType.SERVER);
            createProfile("Client Certificate", ProfileType.CLIENT);
            createProfile("Code Signing", ProfileType.CODE_SIGNING);
            createProfile("Email Protection", ProfileType.EMAIL);
            createProfile("Document Signing", ProfileType.DOCUMENT_SIGNING);
            createProfile("Class 1 Certificate", ProfileType.CLASS_1);
            createProfile("Class 2 Certificate", ProfileType.CLASS_2);
            createProfile("Class 3 Certificate", ProfileType.CLASS_3);
            createProfile("Aadhaar eSign", ProfileType.AADHAAR_ESIGN);
            log.info("Seeded {} default certificate profiles", profileRepository.count());
            auditService.record("system", "SEED", "SEED_PROFILES_CREATED",
                    "count=" + profileRepository.count());
        } catch (Exception e) {
            log.error("Failed to seed default profiles: {}", e.getMessage(), e);
        }
    }

    private void createProfile(String name, ProfileType type) {
        LocalDateTime now = LocalDateTime.now();
        profileRepository.save(CertificateProfile.builder()
                .name(name)
                .description(type.getDescription())
                .type(type.name())
                .keyAlgorithm(type.getKeyAlgorithm())
                .keySize(type.getKeySize())
                .validityDays(type.getValidityDays())
                .caProfile(type.isCaProfile())
                .keyStorage(KeyStorage.DATABASE)
                .keyUsage(type.getKeyUsage())
                .extendedKeyUsage(type.getExtendedKeyUsage())
                .additionalExtensions(List.of())
                .createdBy("system")
                .createdAt(now)
                .updatedAt(now)
                .build());
    }

    private CaEntity createCa(String name, String dn, CaType type, Long parentId) {
        LocalDateTime now = LocalDateTime.now();
        KeyPair keys = cryptoService.generateKeyPair(CryptoService.RSA, 2048);
        String certPem;
        if (type == CaType.ROOT) {
            certPem = cryptoService.buildSelfSignedCaCertificate(dn, keys, 3650, "SHA256withRSA", true, null);
        } else {
            CaEntity parent = caRepository.findById(parentId).orElseThrow();
            certPem = cryptoService.buildSignedCaCertificate(dn, keys,
                    cryptoService.parseCertificate(parent.getCertificatePem()),
                    cryptoService.parsePrivateKey(parent.getPrivateKeyPem()),
                    "SHA256withRSA", 1825, null);
        }
        CaEntity ca = CaEntity.builder()
                .name(name)
                .subjectDn(dn)
                .caType(type)
                .status(CertificateStatus.ISSUED)
                .certificatePem(certPem)
                .privateKeyPem(cryptoService.toPrivateKeyPem(keys.getPrivate()))
                .keyStorage(KeyStorage.DATABASE)
                .keyAlgorithm(CryptoService.RSA)
                .keySize(2048)
                .signatureAlgorithm("SHA256withRSA")
                .serialNumber(cryptoService.parseCertificate(certPem).getSerialNumber().toString(16).toUpperCase())
                .parentCaId(parentId)
                .validFrom(now)
                .validTo(now.plusDays(3650))
                .requestedBy("system")
                .createdAt(now)
                .issuedAt(now)
                .ocspUrl(cryptoService.getOcspUrl())
                .build();
        ca = caRepository.save(ca);
        ca.setCrlDistributionPoint(cryptoService.getCrlUrlBase() + ca.getId());
        return caRepository.save(ca);
    }
}
