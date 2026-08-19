package com.example.dmz;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * End-to-end probe against a LIVE certificate manager + DMZ responder.
 * Skipped unless {@code -Ddmz.baseUrl=http://host:port} is set, e.g.:
 *
 * <pre>
 *   mvn test -Dtest=OcspLiveProbe -Ddmz.baseUrl=http://localhost:8080 \
 *     -Dcm.baseUrl=http://localhost:8089 -Dcm.user=admin -Dcm.password=admin123
 * </pre>
 */
class OcspLiveProbe {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void liveResponderRoundTrip() throws Exception {
        String dmzBase = System.getProperty("dmz.baseUrl");
        Assumptions.assumeTrue(dmzBase != null && !dmzBase.isBlank(), "dmz.baseUrl not set; probe skipped");
        String cmBase = System.getProperty("cm.baseUrl", "http://localhost:8443");
        String user = System.getProperty("cm.user", "admin");
        String password = System.getProperty("cm.password", "admin123");

        HttpClient http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        String auth = "Basic " + Base64.getEncoder().encodeToString((user + ":" + password).getBytes());

        // 1. pick an active CA from the certificate manager
        JsonNode cas = objectMapper.readTree(getString(http, cmBase + "/api/ca/active", auth));
        JsonNode ca = cas.get(0);
        assertNotNull(ca, "CM has no active CA");
        long caId = ca.get("id").asLong();
        String caSerialHex = ca.get("serialNumber").asText();
        X509Certificate caCert = certFromPem(ca.get("certificatePem").asText());

        // 2. issue a leaf certificate for the probe
        KeyPair leafKeyPair = keyPair();
        PKCS10CertificationRequest csr = buildCsr(leafKeyPair);
        JsonNode issued = objectMapper.readTree(postJson(http, cmBase + "/api/certificates/csr", auth,
                Map.of("csrPem", pem(csr), "issuerCaId", caId, "requestedBy", "dmz-live-probe")));
        JsonNode certData = issued.get("data");
        assertNotNull(certData, "CM did not issue the probe certificate");
        BigInteger serial = new BigInteger(certData.get("serialNumber").asText(), 16);

        // 3. build an OCSP request the backend will accept
        DigestCalculatorProvider digests = new JcaDigestCalculatorProviderBuilder().build();
        CertificateID certificateID = new JcaCertificateID(digests.get(CertificateID.HASH_SHA1), caCert, serial);
        OCSPReqBuilder reqBuilder = new OCSPReqBuilder();
        reqBuilder.addRequest(certificateID);
        byte[] ocspReq = reqBuilder.build().getEncoded();

        // 4. POST to the DMZ responder and verify a successful signed response
        byte[] postResp = postBytes(http, dmzBase + "/api/ocsp", "application/ocsp-request", ocspReq);
        OCSPResp parsedPost = new OCSPResp(postResp);
        assertEquals(OCSPRespBuilder.SUCCESSFUL, parsedPost.getStatus());
        BasicOCSPResp basicPost = (BasicOCSPResp) parsedPost.getResponseObject();
        assertEquals(org.bouncycastle.cert.ocsp.CertificateStatus.GOOD,
                basicPost.getResponses()[0].getCertStatus());

        // 5. GET to the DMZ responder (RFC 5019 base64url) must return the same bytes
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(ocspReq);
        byte[] getResp = getBytes(http, dmzBase + "/api/ocsp?request=" + encoded);
        assertArrayEquals(postResp, getResp);

        // 6. ensure a CRL exists on the backend (fresh CM installs have none)
        postJson(http, cmBase + "/api/crl/" + caId + "/generate", auth, Map.of());

        // 7. CRL served by the DMZ by CA serial hex must equal the backend's CRL
        byte[] dmzCrl = getBytes(http, dmzBase + "/api/crl/" + caSerialHex);
        byte[] cmCrl = getBytes(http, cmBase + "/api/crl/" + caId, auth);
        assertArrayEquals(cmCrl, dmzCrl);

        // 8. unknown CA reference must be a 404, not a gateway error
        java.net.http.HttpResponse<String> unknown = http.send(
                HttpRequest.newBuilder(URI.create(dmzBase + "/api/crl/does-not-exist")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(404, unknown.statusCode());
    }

    private String getString(HttpClient http, String url, String auth) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(url))
                .header("Authorization", auth).GET().build(),
                HttpResponse.BodyHandlers.ofString()).body();
    }

    private byte[] getBytes(HttpClient http, String url) throws Exception {
        return getBytes(http, url, null);
    }

    private byte[] getBytes(HttpClient http, String url, String auth) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url)).GET();
        if (auth != null) {
            builder.header("Authorization", auth);
        }
        HttpResponse<byte[]> response = http.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("GET " + url + " -> HTTP " + response.statusCode());
        }
        return response.body();
    }

    private String postJson(HttpClient http, String url, String auth, Map<?, ?> body) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .header("Authorization", auth)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(body)))
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("POST " + url + " -> HTTP " + response.statusCode() + ": " + response.body());
        }
        return response.body();
    }

    private byte[] postBytes(HttpClient http, String url, String contentType, byte[] body) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .header("Content-Type", contentType)
                .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                .build();
        HttpResponse<byte[]> response = http.send(request, HttpResponse.BodyHandlers.ofByteArray());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("POST " + url + " -> HTTP " + response.statusCode());
        }
        return response.body();
    }

    private static KeyPair keyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static PKCS10CertificationRequest buildCsr(KeyPair keyPair) throws Exception {
        JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=dmz-live-probe"), keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(keyPair.getPrivate());
        return builder.build(signer);
    }

    private static String pem(PKCS10CertificationRequest csr) throws Exception {
        StringWriter out = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(out)) {
            writer.writeObject(csr);
        }
        return out.toString();
    }

    private static X509Certificate certFromPem(String pem) throws Exception {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            X509CertificateHolder holder = (X509CertificateHolder) parser.readObject();
            return new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(holder);
        }
    }
}
