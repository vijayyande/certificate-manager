package com.example.dmz.client;

import com.example.dmz.exception.InvalidResponseException;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.Arrays;
import java.util.List;

/**
 * Thin client for the internal certificate manager REST API. Every method
 * validates the response so that only structurally sound CRL/OCSP bytes can be
 * cached and served to external clients.
 */
@Slf4j
@Component
public class CmClient {

    private final RestClient restClient;

    public CmClient(RestClient restClient) {
        this.restClient = restClient;
    }

    /** Fetches the active CA list (id + serial + name) from the backend. */
    public List<CaRef> activeCAs() {
        CaRef[] cas = restClient.get()
                .uri("/api/ca/active")
                .retrieve()
                .body(CaRef[].class);
        return cas == null ? List.of() : Arrays.asList(cas);
    }

    /** Fetches the current CRL for a CA in DER form and validates it. */
    public byte[] fetchCrlDer(long caId) {
        byte[] der = restClient.get()
                .uri("/api/crl/{id}", caId)
                .retrieve()
                .body(byte[].class);
        validateCrl(der, caId);
        return der;
    }

    /** Forwards a raw OCSP request to the backend and validates the response. */
    public byte[] postOcsp(byte[] requestDer) {
        byte[] response = restClient.post()
                .uri("/api/ocsp")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(requestDer)
                .retrieve()
                .body(byte[].class);
        validateOcspResponse(response);
        return response;
    }

    void validateCrl(byte[] der, long caId) {
        if (der == null || der.length == 0) {
            throw new InvalidResponseException("CM returned an empty CRL for CA " + caId, null);
        }
        try {
            new X509CRLHolder(der);
        } catch (Exception e) {
            throw new InvalidResponseException("CM returned an invalid CRL for CA " + caId, e);
        }
    }

    void validateOcspResponse(byte[] der) {
        if (der == null || der.length == 0) {
            throw new InvalidResponseException("CM returned an empty OCSP response", null);
        }
        try {
            new OCSPResp(der);
        } catch (Exception e) {
            throw new InvalidResponseException("CM returned an invalid OCSP response", e);
        }
    }
}
