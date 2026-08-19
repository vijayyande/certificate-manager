package com.example.dmz.service;

import com.example.dmz.cache.TtlCache;
import com.example.dmz.client.CaRef;
import com.example.dmz.client.CmClient;
import com.example.dmz.config.ResponderProperties;
import com.example.dmz.exception.InvalidResponseException;
import com.example.dmz.exception.ResponderException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.ResourceAccessException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Resolves incoming CRL/OCSP protocol requests against the certificate manager
 * and serves the signed bytes it returns. Responses are cached for a short TTL;
 * if the backend is unreachable the last cached entry is served instead of
 * failing, so external clients keep working through outages.
 */
@Slf4j
@Service
public class ResponderService {

    private static final String CA_LIST_KEY = "active-cas";

    private final CmClient cmClient;
    private final ResponderProperties properties;

    private final TtlCache<Long, byte[]> crlCache;
    private final TtlCache<String, byte[]> ocspCache;
    private final TtlCache<String, List<CaRef>> caListCache;

    /**
     * Bounded stripe locks used to deduplicate concurrent refreshes of the same
     * cache key without leaking an unbounded number of lock objects.
     */
    private final Object[] stripes = new Object[64];

    public ResponderService(CmClient cmClient, ResponderProperties properties) {
        this.cmClient = cmClient;
        this.properties = properties;
        this.crlCache = new TtlCache<>(properties.getCrlCacheSeconds() * 1000L);
        this.ocspCache = new TtlCache<>(properties.getOcspCacheSeconds() * 1000L);
        this.caListCache = new TtlCache<>(properties.getCaListCacheSeconds() * 1000L);
        for (int i = 0; i < stripes.length; i++) {
            stripes[i] = new Object();
        }
    }

    /**
     * Serves the current CRL for a CA, addressed by its numeric id, its
     * certificate serial number (as embedded in issued certificates' CDP), or
     * its name.
     */
    public byte[] crl(String caRef) {
        long caId = resolveCaId(caRef);
        try {
            return load(crlCache, caId, () -> cmClient.fetchCrlDer(caId));
        } catch (ResponderException e) {
            throw e;
        } catch (ResourceAccessException e) {
            throw upstreamUnreachable(e);
        } catch (HttpStatusCodeException e) {
            throw translateCrlUpstreamError(e, caRef);
        } catch (InvalidResponseException e) {
            throw new ResponderException(HttpStatus.BAD_GATEWAY, e.getMessage());
        }
    }

    /** Serves an OCSP response for a raw DER OCSP request. */
    public byte[] ocsp(byte[] requestDer) {
        if (requestDer == null || requestDer.length == 0) {
            throw new ResponderException(HttpStatus.BAD_REQUEST, "Empty OCSP request");
        }
        if (requestDer.length > properties.getMaxOcspRequestBytes()) {
            throw new ResponderException(HttpStatus.BAD_REQUEST,
                    "OCSP request exceeds " + properties.getMaxOcspRequestBytes() + " bytes");
        }
        String cacheKey = sha256(requestDer);
        try {
            return load(ocspCache, cacheKey, () -> cmClient.postOcsp(requestDer));
        } catch (ResponderException e) {
            throw e;
        } catch (ResourceAccessException e) {
            throw upstreamUnreachable(e);
        } catch (HttpStatusCodeException e) {
            throw new ResponderException(HttpStatus.SERVICE_UNAVAILABLE,
                    "Certificate manager error (" + e.getStatusCode() + ")");
        } catch (InvalidResponseException e) {
            throw new ResponderException(HttpStatus.BAD_GATEWAY, e.getMessage());
        }
    }

    /** Resolves a CDP reference to the backend's CA id. */
    private long resolveCaId(String caRef) {
        if (caRef == null || caRef.isBlank()) {
            throw new ResponderException(HttpStatus.BAD_REQUEST, "Missing CA reference");
        }
        if (caRef.matches("\\d+")) {
            try {
                return Long.parseLong(caRef);
            } catch (NumberFormatException ignored) {
                // fall through to CA lookup
            }
        }
        String trimmed = caRef.trim();
        for (CaRef ca : activeCAs()) {
            if (ca.serialNumber() != null && ca.serialNumber().equalsIgnoreCase(trimmed)) {
                return ca.id();
            }
            if (ca.name() != null && ca.name().equalsIgnoreCase(trimmed)) {
                return ca.id();
            }
        }
        throw new ResponderException(HttpStatus.NOT_FOUND, "Unknown CA reference: " + caRef);
    }

    private List<CaRef> activeCAs() {
        try {
            return load(caListCache, CA_LIST_KEY, cmClient::activeCAs);
        } catch (ResponderException e) {
            throw e;
        } catch (ResourceAccessException e) {
            throw upstreamUnreachable(e);
        } catch (HttpStatusCodeException e) {
            throw new ResponderException(HttpStatus.SERVICE_UNAVAILABLE,
                    "Certificate manager error (" + e.getStatusCode() + ")");
        }
    }

    /** Cache summary used by the health endpoint. */
    public Map<String, Object> health() {
        return Map.of(
                "status", "UP",
                "cache", Map.of(
                        "crlEntries", crlCache.size(),
                        "ocspEntries", ocspCache.size(),
                        "caListEntries", caListCache.size()));
    }

    /** Clears all cached data (also exposed via a test hook / admin endpoint). */
    public void clearCaches() {
        crlCache.clear();
        ocspCache.clear();
        caListCache.clear();
    }

    private <K, V> V load(TtlCache<K, V> cache, K key, Supplier<V> loader) {
        V fresh = cache.getIfFresh(key);
        if (fresh != null) {
            return fresh;
        }
        synchronized (stripe(key)) {
            V again = cache.getIfFresh(key);
            if (again != null) {
                return again;
            }
            try {
                V value = loader.get();
                cache.put(key, value);
                return value;
            } catch (RuntimeException e) {
                V stale = cache.getIfPresent(key);
                if (stale != null && properties.isServeStaleOnError()) {
                    log.warn("Serving stale cached data for key {} after backend error: {}", key, e.getMessage());
                    return stale;
                }
                throw e;
            }
        }
    }

    private Object stripe(Object key) {
        int idx = (key.hashCode() & 0x7fffffff) % stripes.length;
        return stripes[idx];
    }

    private ResponderException translateCrlUpstreamError(HttpStatusCodeException e, String caRef) {
        if (e.getStatusCode().is4xxClientError()) {
            // The CRL endpoints are public on the backend, so a 4xx there means
            // "no CRL for this CA yet" (or an unknown CA) - surface it as 404 to
            // the CDP client rather than hiding it behind a generic gateway error.
            return new ResponderException(HttpStatus.NOT_FOUND, "CRL not available for CA " + caRef);
        }
        return new ResponderException(HttpStatus.SERVICE_UNAVAILABLE,
                "Certificate manager error (" + e.getStatusCode() + ")");
    }

    private ResponderException upstreamUnreachable(ResourceAccessException e) {
        return new ResponderException(HttpStatus.SERVICE_UNAVAILABLE,
                "Certificate manager unreachable: " + e.getMessage());
    }

    private String sha256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            StringBuilder hex = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                hex.append(String.format(Locale.ROOT, "%02x", b));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
