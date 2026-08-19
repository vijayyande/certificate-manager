package com.example.dmz.client;

import com.example.dmz.exception.InvalidResponseException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestClient;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The real CmClient validates backend bytes structurally so garbage can never
 * enter the responder cache. These tests exercise that validation directly.
 */
class CmClientValidationTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private final CmClient client =
            new CmClient(RestClient.builder().baseUrl("http://localhost:1").build());

    @Test
    void acceptsAValidCrl() throws Exception {
        assertThatCode(() -> client.validateCrl(validCrlDer(), 1L)).doesNotThrowAnyException();
    }

    @Test
    void rejectsGarbageCrl() {
        assertThatThrownBy(() -> client.validateCrl("not a crl".getBytes(), 1L))
                .isInstanceOf(InvalidResponseException.class);
    }

    @Test
    void rejectsEmptyCrl() {
        assertThatThrownBy(() -> client.validateCrl(new byte[0], 1L))
                .isInstanceOf(InvalidResponseException.class);
    }

    @Test
    void acceptsAValidOcspResponse() throws Exception {
        byte[] valid = new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, null).getEncoded();
        assertThatCode(() -> client.validateOcspResponse(valid)).doesNotThrowAnyException();
    }

    @Test
    void rejectsGarbageOcspResponse() {
        assertThatThrownBy(() -> client.validateOcspResponse("garbage".getBytes()))
                .isInstanceOf(InvalidResponseException.class);
    }

    @Test
    void rejectsEmptyOcspResponse() {
        assertThatThrownBy(() -> client.validateOcspResponse(new byte[0]))
                .isInstanceOf(InvalidResponseException.class);
    }

    private static byte[] validCrlDer() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X509v2CRLBuilder builder = new X509v2CRLBuilder(new X500Name("CN=Unit Test CA"), new Date());
        builder.setNextUpdate(new Date(System.currentTimeMillis() + 3_600_000L));
        X509CRLHolder crl = builder.build(
                new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(kp.getPrivate()));
        return crl.getEncoded();
    }
}
