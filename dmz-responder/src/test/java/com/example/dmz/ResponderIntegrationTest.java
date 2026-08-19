package com.example.dmz;

import com.example.dmz.client.CaRef;
import com.example.dmz.client.CmClient;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.security.Security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Routing + caching behaviour with the backend client mocked. The default
 * cache TTLs apply (300s CRL / 60s OCSP), so repeated identical requests must
 * hit the cache and call the backend only once.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ResponderIntegrationTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Autowired
    private TestRestTemplate rest;

    @Autowired
    private com.example.dmz.service.ResponderService service;

    @MockBean
    private CmClient cmClient;

    private byte[] ocspReq;
    private byte[] ocspResp;
    private byte[] crl;

    @BeforeEach
    void setUp() throws Exception {
        service.clearCaches();
        ocspReq = new OCSPReqBuilder().build().getEncoded();
        ocspResp = new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, null).getEncoded();
        crl = validCrlDer();
    }

    /* ---------- OCSP ---------- */

    @Test
    void ocspPostForwardsRequestAndReturnsBackendBytes() {
        when(cmClient.postOcsp(any())).thenReturn(ocspResp);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.parseMediaType("application/ocsp-request"));
        ResponseEntity<byte[]> response = rest.exchange("/api/ocsp", HttpMethod.POST,
                new HttpEntity<>(ocspReq, headers), byte[].class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getHeaders().getContentType().toString()).contains("ocsp-response");
        assertThat(response.getHeaders().getCacheControl()).contains("max-age=60");
        assertThat(response.getBody()).isEqualTo(ocspResp);
        verify(cmClient).postOcsp(ocspReq);
    }

    @Test
    void ocspGetDecodesBase64UrlAndCachesIdenticalRequests() {
        when(cmClient.postOcsp(any())).thenReturn(ocspResp);
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(ocspReq);

        ResponseEntity<byte[]> first = rest.getForEntity(
                UriComponentsBuilder.fromPath("/api/ocsp").queryParam("request", encoded).toUriString(),
                byte[].class);
        ResponseEntity<byte[]> second = rest.getForEntity(
                UriComponentsBuilder.fromPath("/api/ocsp").queryParam("request", encoded).toUriString(),
                byte[].class);

        assertThat(first.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(second.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(first.getBody()).isEqualTo(ocspResp);
        assertThat(second.getBody()).isEqualTo(ocspResp);
        verify(cmClient, times(1)).postOcsp(any());
    }

    @Test
    void ocspGetAcceptsStandardBase64() {
        when(cmClient.postOcsp(any())).thenReturn(ocspResp);
        String encoded = Base64.getEncoder().encodeToString(ocspReq);

        ResponseEntity<byte[]> response = rest.getForEntity(
                UriComponentsBuilder.fromPath("/api/ocsp").queryParam("request", encoded).toUriString(),
                byte[].class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void ocspGetRejectsInvalidEncoding() {
        ResponseEntity<byte[]> response = rest.getForEntity(
                UriComponentsBuilder.fromPath("/api/ocsp").queryParam("request", "!!!not-base64!!!").toUriString(),
                byte[].class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void ocspGetRejectsMissingParameter() {
        ResponseEntity<byte[]> response = rest.getForEntity("/api/ocsp", byte[].class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void ocspRejectsEmptyBody() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.parseMediaType("application/ocsp-request"));
        ResponseEntity<byte[]> response = rest.exchange("/api/ocsp", HttpMethod.POST,
                new HttpEntity<>(new byte[0], headers), byte[].class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void ocspRejectsOversizedRequest() {
        byte[] huge = new byte[20000];
        when(cmClient.postOcsp(any())).thenReturn(ocspResp);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.parseMediaType("application/ocsp-request"));
        ResponseEntity<byte[]> response = rest.exchange("/api/ocsp", HttpMethod.POST,
                new HttpEntity<>(huge, headers), byte[].class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    /* ---------- CRL ---------- */

    @Test
    void crlByNumericIdForwardsAndCaches() {
        when(cmClient.fetchCrlDer(1L)).thenReturn(crl);

        ResponseEntity<byte[]> first = rest.getForEntity("/api/crl/1", byte[].class);
        ResponseEntity<byte[]> second = rest.getForEntity("/api/crl/1", byte[].class);

        assertThat(first.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(first.getHeaders().getContentType().toString()).contains("pkix-crl");
        assertThat(first.getBody()).isEqualTo(crl);
        assertThat(second.getBody()).isEqualTo(crl);
        verify(cmClient, times(1)).fetchCrlDer(1L);
    }

    @Test
    void crlByCaSerialHexResolvesCaseInsensitively() {
        when(cmClient.activeCAs()).thenReturn(List.of(new CaRef(2L, "ABC123", "Demo Root CA")));
        when(cmClient.fetchCrlDer(2L)).thenReturn(crl);

        ResponseEntity<byte[]> lower = rest.getForEntity("/api/crl/abc123", byte[].class);
        assertThat(lower.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(lower.getBody()).isEqualTo(crl);
        verify(cmClient).fetchCrlDer(2L);
    }

    @Test
    void crlByCaNameResolves() {
        when(cmClient.activeCAs()).thenReturn(List.of(new CaRef(3L, "DEF456", "Demo Intermediate CA")));
        when(cmClient.fetchCrlDer(3L)).thenReturn(crl);

        ResponseEntity<byte[]> response = rest.getForEntity(
                UriComponentsBuilder.fromPath("/api/crl/{ca}")
                        .buildAndExpand("Demo Intermediate CA").toUri(),
                byte[].class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        verify(cmClient).fetchCrlDer(3L);
    }

    @Test
    void crlUnknownReferenceIs404() {
        when(cmClient.activeCAs()).thenReturn(List.of(new CaRef(1L, "ABC123", "Root")));
        ResponseEntity<byte[]> response = rest.getForEntity("/api/crl/ZZZZ9999", byte[].class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    /* ---------- health ---------- */

    @Test
    void healthReportsUpWithCacheSizes() {
        when(cmClient.fetchCrlDer(5L)).thenReturn(crl);
        rest.getForEntity("/api/crl/5", byte[].class);

        ResponseEntity<Map> response = rest.getForEntity("/health", Map.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsKey("status");
        assertThat(((Map<?, ?>) response.getBody().get("cache")).get("crlEntries")).isEqualTo(1);
    }

    @Test
    void responsesCarryHardeningHeaders() {
        when(cmClient.fetchCrlDer(5L)).thenReturn(crl);
        ResponseEntity<byte[]> response = rest.getForEntity("/api/crl/5", byte[].class);
        assertThat(response.getHeaders().getFirst("X-Content-Type-Options")).isEqualTo("nosniff");
        assertThat(response.getHeaders().getFirst("X-Frame-Options")).isEqualTo("DENY");
    }

    private static byte[] validCrlDer() throws Exception {
        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        java.security.KeyPair kp = kpg.generateKeyPair();
        org.bouncycastle.asn1.x500.X500Name issuer =
                new org.bouncycastle.asn1.x500.X500Name("CN=DMZ Test CA");
        org.bouncycastle.cert.X509v2CRLBuilder builder =
                new org.bouncycastle.cert.X509v2CRLBuilder(issuer, new java.util.Date());
        builder.setNextUpdate(new java.util.Date(System.currentTimeMillis() + 3_600_000L));
        org.bouncycastle.cert.X509CRLHolder crl = builder.build(
                new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA")
                        .setProvider("BC")
                        .build(kp.getPrivate()));
        return crl.getEncoded();
    }
}
