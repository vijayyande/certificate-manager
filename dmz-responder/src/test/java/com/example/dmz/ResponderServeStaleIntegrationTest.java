package com.example.dmz;

import com.example.dmz.client.CmClient;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.client.ResourceAccessException;

import java.security.Security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.when;

/**
 * Degradation behaviour with a zero CRL cache TTL: the first request loads and
 * immediately expires the entry, so a subsequent backend failure must either
 * serve the stale value (default) or answer 503.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = "cm.crl-cache-seconds=0")
class ResponderServeStaleIntegrationTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Autowired
    private TestRestTemplate rest;

    @MockBean
    private CmClient cmClient;

    private byte[] crl;

    @BeforeEach
    void setUp() throws Exception {
        crl = validCrlDer();
    }

    @Test
    void servesStaleCrlWhenBackendIsUnreachable() {
        when(cmClient.fetchCrlDer(1L))
                .thenReturn(crl)
                .thenThrow(new ResourceAccessException("connect timed out"));

        ResponseEntity<byte[]> first = rest.getForEntity("/api/crl/1", byte[].class);
        assertThat(first.getStatusCode()).isEqualTo(HttpStatus.OK);

        ResponseEntity<byte[]> second = rest.getForEntity("/api/crl/1", byte[].class);
        assertThat(second.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(second.getBody()).isEqualTo(crl);
    }

    @Test
    void returns503WhenBackendIsDownAndNothingIsCached() {
        when(cmClient.fetchCrlDer(anyLong()))
                .thenThrow(new ResourceAccessException("connection refused"));

        ResponseEntity<byte[]> response = rest.getForEntity("/api/crl/9", byte[].class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
    }

    @Test
    void returns404WhenBackendReportsNotFound() {
        when(cmClient.fetchCrlDer(99L))
                .thenThrow(new org.springframework.web.client.HttpClientErrorException(
                        org.springframework.http.HttpStatus.NOT_FOUND));

        ResponseEntity<byte[]> response = rest.getForEntity("/api/crl/99", byte[].class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void returns404WhenBackendHasNoCrlYet() {
        when(cmClient.fetchCrlDer(100L))
                .thenThrow(new org.springframework.web.client.HttpClientErrorException(
                        org.springframework.http.HttpStatus.BAD_REQUEST));

        ResponseEntity<byte[]> response = rest.getForEntity("/api/crl/100", byte[].class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    private static byte[] validCrlDer() throws Exception {
        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        java.security.KeyPair kp = kpg.generateKeyPair();
        org.bouncycastle.cert.X509v2CRLBuilder builder =
                new org.bouncycastle.cert.X509v2CRLBuilder(
                        new org.bouncycastle.asn1.x500.X500Name("CN=DMZ Test CA"), new java.util.Date());
        builder.setNextUpdate(new java.util.Date(System.currentTimeMillis() + 3_600_000L));
        org.bouncycastle.cert.X509CRLHolder crl = builder.build(
                new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA")
                        .setProvider("BC")
                        .build(kp.getPrivate()));
        return crl.getEncoded();
    }
}
