package com.example.cm.service;

import com.example.cm.exception.BusinessException;
import com.example.cm.model.dto.Pkcs11Preset;
import com.example.cm.model.dto.Pkcs11SettingsRequest;
import com.example.cm.model.entity.Pkcs11Settings;
import com.example.cm.repository.Pkcs11SettingsRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/**
 * Bridges the platform to a PKCS#11 device (HSM / smart card / SoftHSM) through
 * the JDK's SunPKCS11 provider. When a CA is configured with {@code PKCS11}
 * key storage its private key is generated on, and never leaves, the token;
 * only the certificate is persisted in the platform database. All signing
 * (CA certificates, leaf certificates, CRLs, OCSP) is then delegated to the
 * token's native {@code C_Sign} operation.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class Pkcs11Service {

    private static final long SETTINGS_ID = 1L;
    private static final String BASE_PROVIDER = "SunPKCS11";
    private static final String DEFAULT_PROVIDER_NAME = "SunPKCS11-CM";

    private final Pkcs11SettingsRepository settingsRepository;
    private final AuditService auditService;

    @Transactional
    public Pkcs11Settings getSettings() {
        return settingsRepository.findById(SETTINGS_ID).orElseGet(() -> {
            Pkcs11Settings settings = Pkcs11Settings.builder()
                    .id(SETTINGS_ID)
                    .providerName(DEFAULT_PROVIDER_NAME)
                    .slotIndex(0)
                    .enabled(false)
                    .keyStorageDefault(com.example.cm.model.enums.KeyStorage.DATABASE)
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .build();
            return settingsRepository.save(settings);
        });
    }

    @Transactional
    public Pkcs11Settings updateSettings(Pkcs11SettingsRequest request) {
        Pkcs11Settings settings = getSettings();
        disconnect();
        settings.setEnabled(request.isEnabled());
        settings.setLibraryPath(request.getLibraryPath() == null ? null : request.getLibraryPath().trim());
        settings.setProviderName(request.getProviderName() == null || request.getProviderName().isBlank()
                ? DEFAULT_PROVIDER_NAME : request.getProviderName().trim());
        settings.setSlotIndex(request.getSlotIndex() == null ? 0 : request.getSlotIndex());
        settings.setTokenPin(request.getTokenPin());
        settings.setKeyStorageDefault(request.getKeyStorageDefault() == null
                ? com.example.cm.model.enums.KeyStorage.DATABASE : request.getKeyStorageDefault());
        settings.setUpdatedAt(LocalDateTime.now());
        settings = settingsRepository.save(settings);
        auditService.record(AuditService.currentActor(), "SETTINGS", "SETTINGS_UPDATED",
                "enabled=" + settings.isEnabled() + ", provider=" + settings.getProviderName()
                        + ", slot=" + settings.getSlotIndex() + ", storageDefault=" + settings.getKeyStorageDefault());
        return settings;
    }

    /** Name the active SunPKCS11 provider is registered under. */
    public String providerName() {
        Pkcs11Settings settings = getSettings();
        return settings.getProviderName() == null || settings.getProviderName().isBlank()
                ? DEFAULT_PROVIDER_NAME : settings.getProviderName();
    }

    /**
     * Well-known PKCS#11 providers the admin can load as a starting point.
     * Each entry carries its typical library paths across operating systems;
     * the recommended one for the current server platform is first.
     */
    public List<Pkcs11Preset> listPresets() {
        String os = System.getProperty("os.name", "").toLowerCase();
        boolean windows = os.contains("win");
        boolean mac = os.contains("mac") || os.contains("darwin");
        return List.of(
                preset("SoftHSM2", "Open-source software HSM ideal for development, testing and local PKI labs.",
                        "SunPKCS11-SoftHSM2", 0, windows, mac,
                        "C:\\Program Files\\SoftHSM2\\lib\\softhsm2.dll",
                        "/usr/lib/softhsm/libsofthsm2.so",
                        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
                        "/usr/local/lib/softhsm2/libsofthsm2.so",
                        "/opt/homebrew/lib/softhsm2/libsofthsm2.so"),
                preset("OpenSC (smart cards)", "Generic PKCS#11 module for smart cards / tokens (CAC, PIV, eID, ...).",
                        "SunPKCS11-OpenSC", 0, windows, mac,
                        "C:\\Program Files\\OpenSC Project\\OpenSC\\pkcs11\\opensc-pkcs11.dll",
                        "C:\\Windows\\System32\\opensc-pkcs11.dll",
                        "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
                        "/usr/lib/opensc-pkcs11.so",
                        "/usr/local/lib/opensc-pkcs11.so",
                        "/Library/OpenSC/lib/opensc-pkcs11.so"),
                preset("YubiKey PIV / YubiHSM", "Yubico PIV smart-card module for YubiKey hardware tokens.",
                        "SunPKCS11-YKCS11", 0, windows, mac,
                        "C:\\Program Files\\Yubico\\Yubico PIV Tool\\bin\\libykcs11.dll",
                        "/usr/lib/libykcs11.so",
                        "/usr/local/lib/libykcs11.so",
                        "/opt/homebrew/lib/libykcs11.dylib",
                        "/Library/Yubico/PIV/libykcs11.dylib"),
                preset("Utimaco CryptoServer", "Utimaco HSM PKCS#11 library (security server / GeneralCrypto).",
                        "SunPKCS11-Utimaco", 0, windows, mac,
                        "C:\\Program Files\\Utimaco\\CryptoServer\\cs_pkcs11_R2.dll",
                        "/opt/utimaco/cryptoserver/pkcs11/libcs_pkcs11_R2.so",
                        "/usr/lib/libcs_pkcs11_R2.so"),
                preset("Thales Luna / SafeNet", "Thales Luna HSM client PKCS#11 library.",
                        "SunPKCS11-Luna", 0, windows, mac,
                        "C:\\Program Files\\SafeNet\\LunaClient\\cryptoki.dll",
                        "C:\\Windows\\System32\\cryptoki.dll",
                        "/usr/safenet/lunaclient/lib/libCryptoki2_64.so",
                        "/Library/Frameworks/P11Kit.framework/Versions/Current/P11Kit"),
                preset("Entrust nShield", "Entrust nShield (nCipher) HSM PKCS#11 toolkit.",
                        "SunPKCS11-nShield", 0, windows, mac,
                        "C:\\Windows\\System32\\nfast\\cknfast.dll",
                        "C:\\Program Files\\nCipher\\nfast\\cknfast.dll",
                        "/opt/nfast/toolkits/pkcs11/libcknfast.so",
                        "/usr/lib/libcknfast.so"),
                preset("Thales eToken / SafeNet eToken", "Gemalto / Thales eToken USB smart-card PKCS#11 module.",
                        "SunPKCS11-eToken", 0, windows, mac,
                        "C:\\Windows\\System32\\eTPKCS11.dll",
                        "/usr/lib/libeTPkcs11.so",
                        "/usr/lib/x86_64-linux-gnu/libeTPkcs11.so",
                        "/Library/Frameworks/eToken.framework/eToken"));
    }

    private Pkcs11Preset preset(String name, String description, String providerName,
                                int slotIndex, boolean windows, boolean mac, String... libraryPaths) {
        List<String> ordered = List.of(libraryPaths).stream()
                .sorted((a, b) -> rank(b, windows, mac) - rank(a, windows, mac))
                .toList();
        return new Pkcs11Preset(name, description, providerName, ordered, ordered.get(0), slotIndex);
    }

    private int rank(String path, boolean windows, boolean mac) {
        String p = path.toLowerCase();
        if (p.contains(".dll") && windows) return 3;
        if (p.contains(".dylib") && mac) return 3;
        if (p.contains(".so") && !windows && !mac) return 3;
        if (p.startsWith("c:\\") && windows) return 2;
        if (p.startsWith("/usr") && !windows) return 2;
        return 1;
    }

    public synchronized void disconnect() {
        String name = providerName();
        Provider active = Security.getProvider(name);
        if (active != null) {
            Security.removeProvider(name);
            auditService.record(AuditService.currentActor(), "SETTINGS", "PKCS11_DISCONNECTED",
                    "provider=" + name);
            log.info("PKCS#11 provider '{}' disconnected", name);
        }
    }

    /**
     * Returns the configured SunPKCS11 provider, (re)creating it from the saved
     * settings on first use. Throws a clear error when PKCS#11 is not enabled or
     * the provider library cannot be loaded.
     */
    public synchronized Provider configureProvider() {
        Pkcs11Settings settings = getSettings();
        if (!settings.isEnabled()) {
            throw new BusinessException("PKCS#11 is not enabled. Enable it in Settings > PKCS#11 device.");
        }
        if (settings.getLibraryPath() == null || settings.getLibraryPath().isBlank()) {
            throw new BusinessException("PKCS#11 library path is not configured");
        }
        String name = providerName();
        Provider existing = Security.getProvider(name);
        if (existing != null) {
            return existing;
        }
        Provider base = Security.getProvider(BASE_PROVIDER);
        if (base == null) {
            throw new BusinessException("The SunPKCS11 provider is not available in this JVM");
        }
        try {
            Provider provider = base.configure(buildConfig(settings));
            Security.addProvider(provider);
            log.info("PKCS#11 provider '{}' loaded (library={}, slot={})",
                    name, settings.getLibraryPath(), settings.getSlotIndex());
            return provider;
        } catch (Exception e) {
            throw new BusinessException("Failed to load PKCS#11 provider '" + name
                    + "': " + e.getMessage(), e);
        }
    }

    private String buildConfig(Pkcs11Settings settings) {
        return "name = " + providerName() + "\n"
                + "library = " + settings.getLibraryPath() + "\n"
                + "slotListIndex = " + settings.getSlotIndex() + "\n"
                + "attributes(*, CKO_PRIVATE_KEY, *) = {\n"
                + "  CKA_TOKEN = true\n"
                + "  CKA_PRIVATE = true\n"
                + "  CKA_SIGN = true\n"
                + "}\n"
                + "attributes(*, CKO_CERTIFICATE, *) = {\n"
                + "  CKA_TOKEN = true\n"
                + "}\n";
    }

    private KeyStore openToken(Provider provider) {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
            String pin = getSettings().getTokenPin();
            keyStore.load(null, pin == null ? new char[0] : pin.toCharArray());
            return keyStore;
        } catch (Exception e) {
            throw new BusinessException("PKCS#11 token connection failed: " + e.getMessage(), e);
        }
    }

    /** Verify the provider loads and the token accepts the PIN + slot. */
    public Map<String, Object> testConnection() {
        Provider provider = configureProvider();
        try {
            KeyStore keyStore = openToken(provider);
            int objects = 0;
            java.util.Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                aliases.nextElement();
                objects++;
            }
            auditService.record(AuditService.currentActor(), "SETTINGS", "PKCS11_TEST",
                    "provider=" + provider.getName() + ", tokenObjects=" + objects);
            return Map.of("connected", true, "provider", provider.getName(), "tokenObjects", objects);
        } catch (BusinessException e) {
            throw e;
        } catch (Exception e) {
            throw new BusinessException("PKCS#11 connection failed: " + e.getMessage(), e);
        }
    }

    /** Generate a key pair directly on the token (CKA_TOKEN = true, CKA_SIGN = true). */
    public KeyPair generateKeyPair(String alias, String algorithm, int keySize) {
        Provider provider = configureProvider();
        openToken(provider); // establishes the user session / login
        try {
            var generator = java.security.KeyPairGenerator.getInstance(algorithm, provider);
            if (com.example.cm.service.CryptoService.EC.equalsIgnoreCase(algorithm)) {
                String curve = keySize >= 521 ? "secp521r1"
                        : keySize >= 384 ? "secp384r1" : "secp256r1";
                generator.initialize(new ECGenParameterSpec(curve));
            } else if (com.example.cm.service.CryptoService.ED25519.equalsIgnoreCase(algorithm)
                    || com.example.cm.service.CryptoService.ED448.equalsIgnoreCase(algorithm)) {
                // EdDSA keys have a fixed size; whether the token supports them at all
                // is only known once generation is attempted (fails gracefully below).
            } else {
                generator.initialize(new RSAKeyGenParameterSpec(
                        keySize > 0 ? keySize : 2048, RSAKeyGenParameterSpec.F4));
            }
            KeyPair keyPair = generator.generateKeyPair();
            if (keyPair.getPrivate() == null) {
                throw new BusinessException("Token did not return a private key for alias '" + alias + "'");
            }
            log.info("Generated {} key on PKCS#11 device for alias '{}'", algorithm, alias);
            return keyPair;
        } catch (BusinessException e) {
            throw e;
        } catch (Exception e) {
            throw new BusinessException("PKCS#11 key generation failed for alias '" + alias
                    + "': " + e.getMessage(), e);
        }
    }

    /** Store the private key entry together with its certificate on the token. */
    public void storeKeyAndCertificate(String alias, PrivateKey key, X509Certificate certificate) {
        Provider provider = configureProvider();
        KeyStore keyStore = openToken(provider);
        try {
            keyStore.setKeyEntry(alias, key, null, new X509Certificate[]{certificate});
            keyStore.store(null);
            log.info("Stored certificate + key for alias '{}' on PKCS#11 device", alias);
        } catch (Exception e) {
            throw new BusinessException("Storing key/certificate on PKCS#11 device failed for alias '"
                    + alias + "': " + e.getMessage(), e);
        }
    }

    /** Load the token-resident private key for signing operations. */
    public PrivateKey getPrivateKey(String alias) {
        Provider provider = configureProvider();
        KeyStore keyStore = openToken(provider);
        try {
            java.security.Key key = keyStore.getKey(alias, null);
            if (key instanceof PrivateKey privateKey) {
                return privateKey;
            }
            throw new BusinessException("No PKCS#11 private key found for alias '" + alias + "'");
        } catch (BusinessException e) {
            throw e;
        } catch (Exception e) {
            throw new BusinessException("Loading PKCS#11 private key for alias '" + alias
                    + "' failed: " + e.getMessage(), e);
        }
    }
}
