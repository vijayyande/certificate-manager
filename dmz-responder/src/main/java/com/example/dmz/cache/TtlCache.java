package com.example.dmz.cache;

import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Minimal thread-safe time-to-live cache. Expired entries are kept around so
 * callers can serve stale data when the upstream backend is unreachable.
 *
 * @param <K> key type
 * @param <V> value type
 */
public final class TtlCache<K, V> {

    private record Entry<V>(V value, Instant expiresAt) {
    }

    private final ConcurrentHashMap<K, Entry<V>> entries = new ConcurrentHashMap<>();
    private final long ttlMillis;

    public TtlCache(long ttlMillis) {
        this.ttlMillis = ttlMillis;
    }

    /** Returns the value only if it is present and not expired, else {@code null}. */
    public V getIfFresh(K key) {
        Entry<V> entry = entries.get(key);
        if (entry == null || entry.expiresAt().isBefore(Instant.now())) {
            return null;
        }
        return entry.value();
    }

    /** Returns any present value (including expired ones), else {@code null}. */
    public V getIfPresent(K key) {
        Entry<V> entry = entries.get(key);
        return entry == null ? null : entry.value();
    }

    public void put(K key, V value) {
        entries.put(key, new Entry<>(value, Instant.now().plusMillis(ttlMillis)));
    }

    public int size() {
        return entries.size();
    }

    public void clear() {
        entries.clear();
    }
}
