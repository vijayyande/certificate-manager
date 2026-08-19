package com.example.cm;

import com.example.cm.model.entity.AuditLog;
import com.example.cm.repository.AuditLogRepository;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;

import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"spring.datasource.url=jdbc:h2:mem:cmtest;DB_CLOSE_DELAY=-1"})
class CertificateManagerIntegrationTest {

    @Autowired
    private TestRestTemplate rest;

    @Autowired
    private AuditLogRepository auditLogRepository;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private HttpHeaders auth(String user, String pass) {
        HttpHeaders headers = new HttpHeaders();
        headers.set(AUTHORIZATION, "Basic " + Base64.getEncoder()
                .encodeToString((user + ":" + pass).getBytes(StandardCharsets.UTF_8)));
        headers.setContentType(MediaType.APPLICATION_JSON);
        return headers;
    }

    @Test
    void t1_infoEndpointWorks() {
        ResponseEntity<Map> resp = rest.exchange("/api/info", HttpMethod.GET,
                new HttpEntity<>(auth("admin", "admin123")), Map.class);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(resp.getBody()).containsKey("counts");
        Map<?, ?> counts = (Map<?, ?>) resp.getBody().get("counts");
        assertThat((Integer) counts.get("casTotal")).isGreaterThanOrEqualTo(2);
    }

    @Test
    void t2_caCreationIsImmediate() {
        // requester must NOT be able to create a CA (admin only)
        Map<String, Object> forbiddenBody = Map.of(
                "name", "Forbidden CA",
                "subjectDn", "CN=Forbidden CA, O=Test, C=US",
                "caType", "ROOT",
                "requestedBy", "requester");
        ResponseEntity<Map> forbidden = rest.exchange("/api/ca", HttpMethod.POST,
                new HttpEntity<>(forbiddenBody, auth("requester", "requester123")), Map.class);
        assertThat(forbidden.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

        // requester cannot list or manage CAs, but can read active CAs (issuer selection)
        ResponseEntity<Map> listForbidden = rest.exchange("/api/ca", HttpMethod.GET,
                new HttpEntity<>(auth("requester", "requester123")), Map.class);
        assertThat(listForbidden.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

        ResponseEntity<List> activeForRequester = rest.exchange("/api/ca/active", HttpMethod.GET,
                new HttpEntity<>(auth("requester", "requester123")), List.class);
        assertThat(activeForRequester.getStatusCode()).isEqualTo(HttpStatus.OK);

        // an admin-created intermediate CA is generated and activated immediately (no approval)
        Map<String, Object> body = Map.of(
                "name", "Integration Test CA",
                "subjectDn", "CN=Integration Test CA, O=Test, C=US",
                "caType", "INTERMEDIATE",
                "parentCaId", 1,
                "keySize", 2048,
                "validityDays", 730,
                "requestedBy", "admin");
        ResponseEntity<Map> created = rest.exchange("/api/ca", HttpMethod.POST,
                new HttpEntity<>(body, auth("admin", "admin123")), Map.class);
        assertThat(created.getStatusCode()).isEqualTo(HttpStatus.OK);
        Map<?, ?> data = (Map<?, ?>) created.getBody().get("data");
        Long caId = Long.valueOf(data.get("id").toString());
        assertThat(data.get("status").toString()).isEqualTo("ISSUED");
        assertThat(data.get("certificatePem")).isNotNull();

        // the CA is active right away and usable as an issuer
        ResponseEntity<Map> ca = rest.exchange("/api/ca/" + caId, HttpMethod.GET,
                new HttpEntity<>(auth("admin", "admin123")), Map.class);
        assertThat(ca.getBody().get("status").toString()).isEqualTo("ISSUED");
        assertThat(ca.getBody().get("certificatePem")).isNotNull();
    }

    @Test
    void t3_csrIssueRevokeCrlOcsp() throws Exception {
        KeyPair kp = generateKeyPair();
        String csrPem = generateCsr(kp, "CN=integration.example.com");
        Map<String, Object> csrBody = Map.of(
                "csrPem", csrPem,
                "issuerCaId", 2,
                "requestedBy", "requester");
        ResponseEntity<Map> submitted = rest.exchange("/api/certificates/csr", HttpMethod.POST,
                new HttpEntity<>(csrBody, auth("requester", "requester123")), Map.class);
        assertThat(submitted.getStatusCode()).isEqualTo(HttpStatus.OK);
        Map<?, ?> certData = (Map<?, ?>) submitted.getBody().get("data");
        Long certId = Long.valueOf(certData.get("id").toString());
        assertThat(certData.get("status").toString()).isEqualTo("ISSUED");

        ResponseEntity<Map> cert = rest.exchange("/api/certificates/" + certId, HttpMethod.GET,
                new HttpEntity<>(auth("requester", "requester123")), Map.class);
        assertThat(cert.getBody().get("status").toString()).isEqualTo("ISSUED");
        String serialHex = cert.getBody().get("serialNumber").toString();
        String certPem = (String) cert.getBody().get("certificatePem");
        assertThat(certPem).contains("BEGIN CERTIFICATE");

        ResponseEntity<String> pemResp = rest.exchange("/api/certificates/" + certId + "/pem", HttpMethod.GET,
                new HttpEntity<>(auth("requester", "requester123")), String.class);
        assertThat(pemResp.getBody()).contains("BEGIN CERTIFICATE");

        // OCSP human-readable check while issued -> GOOD
        ResponseEntity<Map> ocspGood = rest.exchange("/api/ocsp/status/" + serialHex, HttpMethod.GET,
                new HttpEntity<>(auth("admin", "admin123")), Map.class);
        assertThat(((Map<?, ?>) ocspGood.getBody().get("data")).get("status").toString()).contains("GOOD");

        // OCSP binary responder round-trip while issued -> GOOD (BC GOOD is null)
        X509Certificate issuerCert = getIssuerCert();
        BigInteger serial = new BigInteger(serialHex, 16);
        byte[] ocspReq = buildOcspRequest(issuerCert, serial);
        HttpHeaders ocspHeaders = new HttpHeaders();
        ocspHeaders.setContentType(MediaType.parseMediaType("application/ocsp-request"));
        ResponseEntity<byte[]> ocspGoodResp = rest.exchange("/api/ocsp", HttpMethod.POST,
                new HttpEntity<>(ocspReq, ocspHeaders), byte[].class);
        assertThat(ocspGoodResp.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(ocspGoodResp.getHeaders().getContentType().toString()).contains("ocsp-response");
        OCSPResp parsedGood = new OCSPResp(ocspGoodResp.getBody());
        assertThat(parsedGood.getStatus()).isEqualTo(OCSPRespBuilder.SUCCESSFUL);
        org.bouncycastle.cert.ocsp.BasicOCSPResp basicGood =
                (org.bouncycastle.cert.ocsp.BasicOCSPResp) parsedGood.getResponseObject();
        assertThat(basicGood.getResponses()[0].getCertStatus())
                .isEqualTo(org.bouncycastle.cert.ocsp.CertificateStatus.GOOD);

        // revoke (admin only) -> REVOKED, CRL auto-refreshed
        ResponseEntity<Map> revoke = rest.exchange("/api/certificates/" + certId + "/revoke", HttpMethod.POST,
                new HttpEntity<>(Map.of("reason", "KEY_COMPROMISE"), auth("admin", "admin123")), Map.class);
        assertThat(revoke.getStatusCode()).isEqualTo(HttpStatus.OK);

        ResponseEntity<Map> revokedCert = rest.exchange("/api/certificates/" + certId, HttpMethod.GET,
                new HttpEntity<>(auth("requester", "requester123")), Map.class);
        assertThat(revokedCert.getBody().get("status").toString()).isEqualTo("REVOKED");

        // CRL PEM
        ResponseEntity<String> crlPem = rest.exchange("/api/crl/2/pem", HttpMethod.GET,
                new HttpEntity<>(auth("admin", "admin123")), String.class);
        assertThat(crlPem.getBody()).contains("BEGIN X509 CRL");

        // CRL DER
        HttpHeaders plain = auth("admin", "admin123");
        plain.setContentType(MediaType.APPLICATION_JSON);
        ResponseEntity<byte[]> crlDer = rest.exchange("/api/crl/2", HttpMethod.GET,
                new HttpEntity<>(plain), byte[].class);
        assertThat(crlDer.getBody()).isNotEmpty();
        assertThat(crlDer.getHeaders().getContentType().toString()).contains("pkix-crl");

        // OCSP binary responder round-trip (revoked -> RevokedStatus in the response)
        X509Certificate revokedIssuerCert = getIssuerCert();
        BigInteger revokedSerial = new BigInteger(serialHex, 16);
        byte[] revokedOcspReq = buildOcspRequest(revokedIssuerCert, revokedSerial);
        HttpHeaders revokedOcspHeaders = new HttpHeaders();
        revokedOcspHeaders.setContentType(MediaType.parseMediaType("application/ocsp-request"));
        ResponseEntity<byte[]> ocspResp = rest.exchange("/api/ocsp", HttpMethod.POST,
                new HttpEntity<>(revokedOcspReq, revokedOcspHeaders), byte[].class);
        assertThat(ocspResp.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(ocspResp.getHeaders().getContentType().toString()).contains("ocsp-response");

        OCSPResp parsed = new OCSPResp(ocspResp.getBody());
        assertThat(parsed.getStatus()).isEqualTo(OCSPRespBuilder.SUCCESSFUL);
        org.bouncycastle.cert.ocsp.BasicOCSPResp basic =
                (org.bouncycastle.cert.ocsp.BasicOCSPResp) parsed.getResponseObject();
        SingleResp single = basic.getResponses()[0];
        assertThat(single.getCertStatus()).isInstanceOf(RevokedStatus.class);
        assertThat(((RevokedStatus) single.getCertStatus()).getRevocationReason())
                .isEqualTo(CRLReason.keyCompromise);
    }

    @Test
    void t4_authorization() throws Exception {
        // a certificate request is issued immediately, without any approver
        KeyPair kp = generateKeyPair();
        String csrPem = generateCsr(kp, "CN=no-approval.example.com");
        Map<String, Object> csrBody = Map.of(
                "csrPem", csrPem,
                "issuerCaId", 2,
                "requestedBy", "requester");
        ResponseEntity<Map> submitted = rest.exchange("/api/certificates/csr", HttpMethod.POST,
                new HttpEntity<>(csrBody, auth("requester", "requester123")), Map.class);
        assertThat(submitted.getStatusCode()).isEqualTo(HttpStatus.OK);
        Long certId = Long.valueOf(((Map<?, ?>) submitted.getBody().get("data")).get("id").toString());
        assertThat(((Map<?, ?>) submitted.getBody().get("data")).get("status").toString()).isEqualTo("ISSUED");

        // a requester cannot revoke or suspend certificates (admin only)
        ResponseEntity<Map> revokeForbidden = rest.exchange("/api/certificates/" + certId + "/revoke", HttpMethod.POST,
                new HttpEntity<>(Map.of("reason", "SUPERSEDED"), auth("requester", "requester123")), Map.class);
        assertThat(revokeForbidden.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

        ResponseEntity<Map> suspendForbidden = rest.exchange("/api/certificates/" + certId + "/suspend", HttpMethod.POST,
                new HttpEntity<>(Map.of(), auth("requester", "requester123")), Map.class);
        assertThat(suspendForbidden.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

        // a requester cannot generate a CRL manually (admin only; CRLs refresh automatically)
        ResponseEntity<Map> crlForbidden = rest.exchange("/api/crl/2/generate", HttpMethod.POST,
                new HttpEntity<>(Map.of(), auth("requester", "requester123")), Map.class);
        assertThat(crlForbidden.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

        // admin can revoke
        ResponseEntity<Map> revoke = rest.exchange("/api/certificates/" + certId + "/revoke", HttpMethod.POST,
                new HttpEntity<>(Map.of("reason", "SUPERSEDED"), auth("admin", "admin123")), Map.class);
        assertThat(revoke.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void t5_rolesAndRemovedEndpoints() {
        // current-user endpoint exposes roles
        ResponseEntity<Map> me = rest.exchange("/api/me", HttpMethod.GET,
                new HttpEntity<>(auth("requester", "requester123")), Map.class);
        assertThat(me.getBody().get("username")).isEqualTo("requester");
        List<String> requesterRoles = (List<String>) me.getBody().get("roles");
        assertThat(requesterRoles).contains("REQUESTER");
        assertThat(requesterRoles).doesNotContain("ADMIN");

        ResponseEntity<Map> adminMe = rest.exchange("/api/me", HttpMethod.GET,
                new HttpEntity<>(auth("admin", "admin123")), Map.class);
        List<String> adminRoles = (List<String>) adminMe.getBody().get("roles");
        assertThat(adminRoles).contains("ADMIN", "REQUESTER");

        // the approval workflow is gone: /api/config and /api/approvals no longer exist
        ResponseEntity<Map> cfgGone = rest.exchange("/api/config", HttpMethod.GET,
                new HttpEntity<>(auth("admin", "admin123")), Map.class);
        assertThat(cfgGone.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);

        ResponseEntity<Map> approvalsGone = rest.exchange("/api/approvals", HttpMethod.GET,
                new HttpEntity<>(auth("admin", "admin123")), Map.class);
        assertThat(approvalsGone.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);

        ResponseEntity<Map> pendingGone = rest.exchange("/api/approvals/pending", HttpMethod.GET,
                new HttpEntity<>(auth("admin", "admin123")), Map.class);
        assertThat(pendingGone.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void t6_manualCertificateRequestFlow() throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("commonName", "manual.example.com");
        body.put("organization", "Manual Corp");
        body.put("country", "US");
        body.put("state", "CA");
        body.put("dnsNames", List.of("manual.example.com", "www.manual.example.com"));
        body.put("ipAddresses", List.of("10.1.2.3"));
        body.put("keyAlgorithm", "RSA");
        body.put("keySize", 2048);
        body.put("validityDays", 365);
        body.put("issuerCaId", 2);
        body.put("requestedBy", "requester");
        ResponseEntity<Map> submitted = rest.exchange("/api/certificates/request", HttpMethod.POST,
                new HttpEntity<>(body, auth("requester", "requester123")), Map.class);
        assertThat(submitted.getStatusCode()).isEqualTo(HttpStatus.OK);
        Map<?, ?> certData = (Map<?, ?>) submitted.getBody().get("data");
        Long certId = Long.valueOf(certData.get("id").toString());
        assertThat(certData.get("status").toString()).isEqualTo("ISSUED");

        ResponseEntity<Map> cert = rest.exchange("/api/certificates/" + certId, HttpMethod.GET,
                new HttpEntity<>(auth("requester", "requester123")), Map.class);
        assertThat(cert.getBody().get("status").toString()).isEqualTo("ISSUED");
        assertThat(cert.getBody().get("subjectDn").toString()).contains("CN=manual.example.com");
        assertThat(cert.getBody().get("privateKeyAvailable")).isEqualTo(true);
        assertThat(cert.getBody().containsKey("privateKeyPem")).isFalse();

        // owner can download the generated private key
        ResponseEntity<String> key = rest.exchange("/api/certificates/" + certId + "/key", HttpMethod.GET,
                new HttpEntity<>(auth("requester", "requester123")), String.class);
        assertThat(key.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(key.getBody()).contains("PRIVATE KEY");

        // even an admin cannot download the key - only the requester/owner can
        ResponseEntity<String> keyAdminForbidden = rest.exchange("/api/certificates/" + certId + "/key", HttpMethod.GET,
                new HttpEntity<>(auth("admin", "admin123")), String.class);
        assertThat(keyAdminForbidden.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

        // SANs from the request are present on the issued certificate
        List<String> sans = sansOf((String) cert.getBody().get("certificatePem"));
        assertThat(sans).contains("manual.example.com", "www.manual.example.com", "10.1.2.3");
    }

    @Test
    void t7_certificateProfiles() throws Exception {
        // requester can read profiles but not create them
        ResponseEntity<List> profiles = rest.exchange("/api/profiles", HttpMethod.GET,
                new HttpEntity<>(auth("requester", "requester123")), List.class);
        assertThat(profiles.getStatusCode()).isEqualTo(HttpStatus.OK);
        List<?> allProfiles = profiles.getBody();
        assertThat(allProfiles).isNotEmpty();
        Map<?, ?> sslProfile = findProfile(allProfiles, "SSL Certificate");
        Map<?, ?> caProfile = findProfile(allProfiles, "CA Certificate");
        assertThat(sslProfile).isNotNull();
        assertThat(caProfile).isNotNull();

        ResponseEntity<Map> createForbidden = rest.exchange("/api/profiles", HttpMethod.POST,
                new HttpEntity<>(profileBody("Requester Profile"), auth("requester", "requester123")), Map.class);
        assertThat(createForbidden.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

        // admin can create a profile
        ResponseEntity<Map> created = rest.exchange("/api/profiles", HttpMethod.POST,
                new HttpEntity<>(profileBody("Integration Profile"), auth("admin", "admin123")), Map.class);
        assertThat(created.getStatusCode()).isEqualTo(HttpStatus.OK);
        Long newProfileId = Long.valueOf(((Map<?, ?>) created.getBody().get("data")).get("id").toString());

        // duplicate names are rejected
        ResponseEntity<Map> duplicate = rest.exchange("/api/profiles", HttpMethod.POST,
                new HttpEntity<>(profileBody("Integration Profile"), auth("admin", "admin123")), Map.class);
        assertThat(duplicate.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

        // requester cannot use a CA profile
        Long caProfileId = Long.valueOf(caProfile.get("id").toString());
        Map<String, Object> caBody = baseRequest("ca-profile.example.com");
        caBody.put("profileId", caProfileId);
        ResponseEntity<Map> caRejected = rest.exchange("/api/certificates/request", HttpMethod.POST,
                new HttpEntity<>(caBody, auth("requester", "requester123")), Map.class);
        assertThat(caRejected.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

        // requester uses the SSL profile + an extra custom OID; issued immediately
        Long sslProfileId = Long.valueOf(sslProfile.get("id").toString());
        Map<String, Object> body = baseRequest("profile.example.com");
        body.put("profileId", sslProfileId);
        body.put("additionalExtensions", List.of(
                Map.of("oid", "1.2.3.4.5.6.7.8", "type", "STRING", "value", "profile-extension")));
        ResponseEntity<Map> submitted = rest.exchange("/api/certificates/request", HttpMethod.POST,
                new HttpEntity<>(body, auth("requester", "requester123")), Map.class);
        assertThat(submitted.getStatusCode()).isEqualTo(HttpStatus.OK);
        Map<?, ?> certData = (Map<?, ?>) submitted.getBody().get("data");
        Long certId = Long.valueOf(certData.get("id").toString());
        assertThat(certData.get("profileName").toString()).isEqualTo("SSL Certificate");
        assertThat(certData.get("status").toString()).isEqualTo("ISSUED");

        ResponseEntity<Map> cert = rest.exchange("/api/certificates/" + certId, HttpMethod.GET,
                new HttpEntity<>(auth("requester", "requester123")), Map.class);
        assertThat(cert.getBody().get("status").toString()).isEqualTo("ISSUED");
        String certPem = (String) cert.getBody().get("certificatePem");

        // profile-derived keyUsage / extendedKeyUsage and the custom OID are embedded
        org.bouncycastle.cert.X509CertificateHolder holder = certHolder(certPem);
        KeyUsage ku = KeyUsage.getInstance(holder.getExtension(Extension.keyUsage).getParsedValue());
        assertThat(ku.hasUsages(KeyUsage.digitalSignature)).isTrue();
        assertThat(ku.hasUsages(KeyUsage.keyEncipherment)).isTrue();
        ExtendedKeyUsage eku = ExtendedKeyUsage.getInstance(
                holder.getExtension(Extension.extendedKeyUsage).getParsedValue());
        assertThat(eku.hasKeyPurposeId(KeyPurposeId.id_kp_serverAuth)).isTrue();
        org.bouncycastle.asn1.ASN1ObjectIdentifier customOid =
                new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.2.3.4.5.6.7.8");
        assertThat(holder.getExtension(customOid)).isNotNull();
        assertThat(org.bouncycastle.asn1.DERUTF8String.getInstance(
                holder.getExtension(customOid).getParsedValue()).getString())
                .isEqualTo("profile-extension");

        // admin can delete a profile
        ResponseEntity<Map> deleted = rest.exchange("/api/profiles/" + newProfileId, HttpMethod.DELETE,
                new HttpEntity<>(auth("admin", "admin123")), Map.class);
        assertThat(deleted.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void t8_minuteValidity() throws Exception {
        // request-level validity in minutes (as short as 1 minute), issued immediately
        Map<String, Object> body = baseRequest("one-minute.example.com");
        body.put("validityMinutes", 1);
        ResponseEntity<Map> submitted = rest.exchange("/api/certificates/request", HttpMethod.POST,
                new HttpEntity<>(body, auth("requester", "requester123")), Map.class);
        assertThat(submitted.getStatusCode()).isEqualTo(HttpStatus.OK);
        Map<?, ?> certData = (Map<?, ?>) submitted.getBody().get("data");
        Long certId = Long.valueOf(certData.get("id").toString());
        assertThat(certData.get("validityMinutes").toString()).isEqualTo("1");
        assertThat(certData.get("status").toString()).isEqualTo("ISSUED");

        ResponseEntity<Map> cert = rest.exchange("/api/certificates/" + certId, HttpMethod.GET,
                new HttpEntity<>(auth("requester", "requester123")), Map.class);
        assertThat(cert.getBody().get("status").toString()).isEqualTo("ISSUED");
        long seconds = Duration.between(
                LocalDateTime.parse(cert.getBody().get("validFrom").toString()),
                LocalDateTime.parse(cert.getBody().get("validTo").toString())).getSeconds();
        assertThat(seconds).isBetween(50L, 120L);

        // profile-level validity in minutes overrides the profile's day value
        Map<String, Object> pBody = profileBody("Minute Profile");
        pBody.put("validityMinutes", 90);
        ResponseEntity<Map> created = rest.exchange("/api/profiles", HttpMethod.POST,
                new HttpEntity<>(pBody, auth("admin", "admin123")), Map.class);
        assertThat(created.getStatusCode()).isEqualTo(HttpStatus.OK);
        Long profileId = Long.valueOf(((Map<?, ?>) created.getBody().get("data")).get("id").toString());

        Map<String, Object> body2 = baseRequest("profile-minute.example.com");
        body2.put("profileId", profileId);
        ResponseEntity<Map> submitted2 = rest.exchange("/api/certificates/request", HttpMethod.POST,
                new HttpEntity<>(body2, auth("requester", "requester123")), Map.class);
        Map<?, ?> certData2 = (Map<?, ?>) submitted2.getBody().get("data");
        Long certId2 = Long.valueOf(certData2.get("id").toString());
        assertThat(certData2.get("validityMinutes").toString()).isEqualTo("90");
        assertThat(certData2.get("status").toString()).isEqualTo("ISSUED");

        ResponseEntity<Map> cert2 = rest.exchange("/api/certificates/" + certId2, HttpMethod.GET,
                new HttpEntity<>(auth("requester", "requester123")), Map.class);
        assertThat(cert2.getBody().get("status").toString()).isEqualTo("ISSUED");
        long seconds2 = Duration.between(
                LocalDateTime.parse(cert2.getBody().get("validFrom").toString()),
                LocalDateTime.parse(cert2.getBody().get("validTo").toString())).getSeconds();
        assertThat(seconds2).isBetween(4800L, 6000L);
    }

    @Test
    void t9_profileTypes() throws Exception {
        // the built-in types are exposed with their preset parameters
        ResponseEntity<List> types = rest.exchange("/api/profiles/types", HttpMethod.GET,
                new HttpEntity<>(auth("requester", "requester123")), List.class);
        assertThat(types.getStatusCode()).isEqualTo(HttpStatus.OK);
        List<String> codes = types.getBody().stream()
                .map(t -> String.valueOf(((Map<?, ?>) t).get("code"))).toList();
        for (String c : List.of("CUSTOM", "CA", "SERVER", "CLIENT", "CODE_SIGNING", "EMAIL",
                "DOCUMENT_SIGNING", "CLASS_1", "CLASS_2", "CLASS_3", "AADHAAR_ESIGN")) {
            assertThat(codes).contains(c);
        }

        // creating a profile with only a type applies the preset defaults server-side
        Map<String, Object> csBody = new LinkedHashMap<>();
        csBody.put("name", "CS Preset");
        csBody.put("type", "CODE_SIGNING");
        ResponseEntity<Map> cs = rest.exchange("/api/profiles", HttpMethod.POST,
                new HttpEntity<>(csBody, auth("admin", "admin123")), Map.class);
        assertThat(cs.getStatusCode()).isEqualTo(HttpStatus.OK);
        Map<?, ?> csProfile = (Map<?, ?>) cs.getBody().get("data");
        assertThat(csProfile.get("type").toString()).isEqualTo("CODE_SIGNING");
        assertThat(csProfile.get("keyAlgorithm").toString()).isEqualTo("RSA");
        assertThat(csProfile.get("keySize").toString()).isEqualTo("2048");
        assertThat(csProfile.get("validityDays").toString()).isEqualTo("365");
        assertThat(csProfile.get("keyUsage")).isEqualTo(List.of("digitalSignature", "nonRepudiation"));
        assertThat(csProfile.get("extendedKeyUsage")).isEqualTo(List.of("codeSigning"));

        Map<String, Object> eSignBody = new LinkedHashMap<>();
        eSignBody.put("name", "Aadhaar Preset");
        eSignBody.put("type", "AADHAAR_ESIGN");
        ResponseEntity<Map> eSign = rest.exchange("/api/profiles", HttpMethod.POST,
                new HttpEntity<>(eSignBody, auth("admin", "admin123")), Map.class);
        assertThat(eSign.getStatusCode()).isEqualTo(HttpStatus.OK);
        Map<?, ?> esignProfile = (Map<?, ?>) eSign.getBody().get("data");
        assertThat(esignProfile.get("type").toString()).isEqualTo("AADHAAR_ESIGN");
        assertThat(esignProfile.get("extendedKeyUsage")).isEqualTo(List.of("emailProtection"));

        // a certificate requested through the code-signing preset embeds its KU / EKU
        Long csProfileId = Long.valueOf(csProfile.get("id").toString());
        Map<String, Object> body = baseRequest("codesign.example.com");
        body.put("profileId", csProfileId);
        ResponseEntity<Map> submitted = rest.exchange("/api/certificates/request", HttpMethod.POST,
                new HttpEntity<>(body, auth("requester", "requester123")), Map.class);
        assertThat(submitted.getStatusCode()).isEqualTo(HttpStatus.OK);
        Long certId = Long.valueOf(((Map<?, ?>) submitted.getBody().get("data")).get("id").toString());
        ResponseEntity<Map> cert = rest.exchange("/api/certificates/" + certId, HttpMethod.GET,
                new HttpEntity<>(auth("requester", "requester123")), Map.class);
        assertThat(cert.getBody().get("status").toString()).isEqualTo("ISSUED");
        String certPem = (String) cert.getBody().get("certificatePem");
        org.bouncycastle.cert.X509CertificateHolder holder = certHolder(certPem);
        KeyUsage ku = KeyUsage.getInstance(holder.getExtension(Extension.keyUsage).getParsedValue());
        assertThat(ku.hasUsages(KeyUsage.digitalSignature)).isTrue();
        assertThat(ku.hasUsages(KeyUsage.nonRepudiation)).isTrue();
        ExtendedKeyUsage eku = ExtendedKeyUsage.getInstance(
                holder.getExtension(Extension.extendedKeyUsage).getParsedValue());
        assertThat(eku.hasKeyPurposeId(KeyPurposeId.id_kp_codeSigning)).isTrue();
    }

    @Test
    void t10_pkcs11Settings() {
        // PKCS#11 administration is admin-only
        ResponseEntity<Map> forbidden = rest.exchange("/api/pkcs11", HttpMethod.GET,
                new HttpEntity<>(auth("requester", "requester123")), Map.class);
        assertThat(forbidden.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

        // defaults: disabled, database key storage, PIN never serialized back
        ResponseEntity<Map> defaults = rest.exchange("/api/pkcs11", HttpMethod.GET,
                new HttpEntity<>(auth("admin", "admin123")), Map.class);
        assertThat(defaults.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(defaults.getBody().get("keyStorageDefault").toString()).isEqualTo("DATABASE");
        assertThat(defaults.getBody().get("enabled").toString()).isEqualTo("false");
        assertThat(defaults.getBody()).doesNotContainKey("tokenPin");

        // requesting a PKCS11-backed CA while the device is disabled must be rejected
        Map<String, Object> p11Disabled = new LinkedHashMap<>();
        p11Disabled.put("enabled", false);
        p11Disabled.put("keyStorageDefault", "DATABASE");
        rest.exchange("/api/pkcs11", HttpMethod.POST,
                new HttpEntity<>(p11Disabled, auth("admin", "admin123")), Map.class);

        Map<String, Object> caBody = new LinkedHashMap<>();
        caBody.put("name", "P11 Rejected CA");
        caBody.put("subjectDn", "CN=P11 Rejected CA, O=Test, C=US");
        caBody.put("caType", "INTERMEDIATE");
        caBody.put("parentCaId", 1);
        caBody.put("keySize", 2048);
        caBody.put("validityDays", 365);
        caBody.put("keyStorage", "PKCS11");
        caBody.put("requestedBy", "admin");
        ResponseEntity<Map> rejected = rest.exchange("/api/ca", HttpMethod.POST,
                new HttpEntity<>(caBody, auth("admin", "admin123")), Map.class);
        assertThat(rejected.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

        // enable the device with a bogus library; saving works, connection test fails gracefully
        Map<String, Object> enabled = new LinkedHashMap<>();
        enabled.put("enabled", true);
        enabled.put("providerName", "SunPKCS11-CM");
        enabled.put("libraryPath", "C:/nonexistent/softhsm2.dll");
        enabled.put("slotIndex", 0);
        enabled.put("tokenPin", "1234");
        enabled.put("keyStorageDefault", "PKCS11");
        ResponseEntity<Map> saved = rest.exchange("/api/pkcs11", HttpMethod.POST,
                new HttpEntity<>(enabled, auth("admin", "admin123")), Map.class);
        assertThat(saved.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(saved.getBody().get("data")).isNotNull();
        assertThat(saved.getBody()).doesNotContainKey("tokenPin");

        ResponseEntity<Map> afterSave = rest.exchange("/api/pkcs11", HttpMethod.GET,
                new HttpEntity<>(auth("admin", "admin123")), Map.class);
        assertThat(afterSave.getBody().get("enabled").toString()).isEqualTo("true");
        assertThat(afterSave.getBody().get("keyStorageDefault").toString()).isEqualTo("PKCS11");

        ResponseEntity<Map> testFail = rest.exchange("/api/pkcs11/test", HttpMethod.POST,
                new HttpEntity<>(Map.of(), auth("admin", "admin123")), Map.class);
        assertThat(testFail.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

        // a PKCS11-backed CA fails fast at request time when the token cannot be reached
        // (the CA is generated synchronously, so key generation errors surface immediately)
        Map<String, Object> caBody2 = new LinkedHashMap<>();
        caBody2.put("name", "P11 Unreachable CA");
        caBody2.put("subjectDn", "CN=P11 Unreachable CA, O=Test, C=US");
        caBody2.put("caType", "INTERMEDIATE");
        caBody2.put("parentCaId", 1);
        caBody2.put("keySize", 2048);
        caBody2.put("validityDays", 365);
        caBody2.put("keyStorage", "PKCS11");
        caBody2.put("pkcs11Alias", "p11-ca-token");
        caBody2.put("requestedBy", "admin");
        ResponseEntity<Map> failFast = rest.exchange("/api/ca", HttpMethod.POST,
                new HttpEntity<>(caBody2, auth("admin", "admin123")), Map.class);
        assertThat(failFast.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

        // with DATABASE as the default storage, a CA request omitting storage uses the default
        // and is issued immediately (DATABASE keys need no device)
        Map<String, Object> dbDefault = new LinkedHashMap<>();
        dbDefault.put("enabled", true);
        dbDefault.put("providerName", "SunPKCS11-CM");
        dbDefault.put("libraryPath", "C:/nonexistent/softhsm2.dll");
        dbDefault.put("slotIndex", 0);
        dbDefault.put("tokenPin", "");
        dbDefault.put("keyStorageDefault", "DATABASE");
        rest.exchange("/api/pkcs11", HttpMethod.POST,
                new HttpEntity<>(dbDefault, auth("admin", "admin123")), Map.class);

        Map<String, Object> caBody3 = new LinkedHashMap<>();
        caBody3.put("name", "Default Storage CA");
        caBody3.put("subjectDn", "CN=Default Storage CA, O=Test, C=US");
        caBody3.put("caType", "INTERMEDIATE");
        caBody3.put("parentCaId", 1);
        caBody3.put("keySize", 2048);
        caBody3.put("validityDays", 365);
        caBody3.put("requestedBy", "admin");
        ResponseEntity<Map> defaulted = rest.exchange("/api/ca", HttpMethod.POST,
                new HttpEntity<>(caBody3, auth("admin", "admin123")), Map.class);
        assertThat(defaulted.getStatusCode()).isEqualTo(HttpStatus.OK);
        Map<?, ?> defaultedData = (Map<?, ?>) defaulted.getBody().get("data");
        assertThat(defaultedData.get("keyStorage").toString()).isEqualTo("DATABASE");
        assertThat(defaultedData.get("status").toString()).isEqualTo("ISSUED");

        // restore platform defaults
        rest.exchange("/api/pkcs11", HttpMethod.POST,
                new HttpEntity<>(p11Disabled, auth("admin", "admin123")), Map.class);
    }

    @Test
    void t11_pkcs11Presets() {
        // presets are admin-only
        ResponseEntity<Map> forbidden = rest.exchange("/api/pkcs11/presets", HttpMethod.GET,
                new HttpEntity<>(auth("requester", "requester123")), Map.class);
        assertThat(forbidden.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

        ResponseEntity<List> presets = rest.exchange("/api/pkcs11/presets", HttpMethod.GET,
                new HttpEntity<>(auth("admin", "admin123")), List.class);
        assertThat(presets.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(presets.getBody()).isNotEmpty();

        List<String> names = presets.getBody().stream()
                .map(p -> String.valueOf(((Map<?, ?>) p).get("name"))).toList();
        for (String expected : List.of("SoftHSM2", "OpenSC (smart cards)", "YubiKey PIV / YubiHSM",
                "Utimaco CryptoServer", "Thales Luna / SafeNet", "Entrust nShield",
                "Thales eToken / SafeNet eToken")) {
            assertThat(names).contains(expected);
        }

        for (Object o : presets.getBody()) {
            Map<?, ?> p = (Map<?, ?>) o;
            assertThat(p.get("providerName").toString()).startsWith("SunPKCS11-");
            assertThat(p.get("libraryPaths")).isInstanceOf(List.class);
            assertThat(((List<?>) p.get("libraryPaths"))).isNotEmpty();
            assertThat(p.get("libraryPath")).isNotNull();
            // the recommended path must be one of the known paths
            assertThat((List<Object>) p.get("libraryPaths")).contains(p.get("libraryPath"));
        }

        // a preset's fields can feed a settings save (customized as needed)
        Map<?, ?> softHsm = (Map<?, ?>) presets.getBody().stream()
                .filter(p -> "SoftHSM2".equals(((Map<?, ?>) p).get("name"))).findFirst().orElseThrow();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("enabled", false);
        body.put("providerName", softHsm.get("providerName"));
        body.put("libraryPath", softHsm.get("libraryPath"));
        body.put("slotIndex", 0);
        body.put("tokenPin", "");
        body.put("keyStorageDefault", "DATABASE");
        ResponseEntity<Map> saved = rest.exchange("/api/pkcs11", HttpMethod.POST,
                new HttpEntity<>(body, auth("admin", "admin123")), Map.class);
        assertThat(saved.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(((Map<?, ?>) saved.getBody().get("data")).get("providerName").toString())
                .isEqualTo(softHsm.get("providerName").toString());

        // restore defaults
        Map<String, Object> reset = new LinkedHashMap<>();
        reset.put("enabled", false);
        reset.put("keyStorageDefault", "DATABASE");
        rest.exchange("/api/pkcs11", HttpMethod.POST,
                new HttpEntity<>(reset, auth("admin", "admin123")), Map.class);
    }

    @Test
    void t12_profileKeyStorage() {
        // profiles default to DATABASE storage
        ResponseEntity<Map> created = rest.exchange("/api/profiles", HttpMethod.POST,
                new HttpEntity<>(profileBody("Storage Profile"), auth("admin", "admin123")), Map.class);
        assertThat(created.getStatusCode()).isEqualTo(HttpStatus.OK);
        Map<?, ?> data = (Map<?, ?>) created.getBody().get("data");
        assertThat(data.get("keyStorage").toString()).isEqualTo("DATABASE");
        Long profileId = Long.valueOf(data.get("id").toString());

        // admin can create a PKCS#11-storage profile even while the device is disabled
        Map<String, Object> p11Body = profileBody("HSM Storage Profile");
        p11Body.put("keyStorage", "PKCS11");
        ResponseEntity<Map> p11Created = rest.exchange("/api/profiles", HttpMethod.POST,
                new HttpEntity<>(p11Body, auth("admin", "admin123")), Map.class);
        assertThat(p11Created.getStatusCode()).isEqualTo(HttpStatus.OK);
        Map<?, ?> p11Data = (Map<?, ?>) p11Created.getBody().get("data");
        assertThat(p11Data.get("keyStorage").toString()).isEqualTo("PKCS11");
        Long p11ProfileId = Long.valueOf(p11Data.get("id").toString());

        // ...but a request using that profile is rejected while the device is not configured
        Map<String, Object> body = baseRequest("hsm-required.example.com");
        body.put("profileId", p11ProfileId);
        ResponseEntity<Map> rejected = rest.exchange("/api/certificates/request", HttpMethod.POST,
                new HttpEntity<>(body, auth("requester", "requester123")), Map.class);
        assertThat(rejected.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(rejected.getBody().get("message").toString()).contains("PKCS#11");

        // a request on the DATABASE profile keeps the exportable key in the platform DB
        Map<String, Object> dbBody = baseRequest("db-backed.example.com");
        dbBody.put("profileId", profileId);
        ResponseEntity<Map> submitted = rest.exchange("/api/certificates/request", HttpMethod.POST,
                new HttpEntity<>(dbBody, auth("requester", "requester123")), Map.class);
        assertThat(submitted.getStatusCode()).isEqualTo(HttpStatus.OK);
        Map<?, ?> certData = (Map<?, ?>) submitted.getBody().get("data");
        assertThat(certData.get("keyStorage").toString()).isEqualTo("DATABASE");
        Long certId = Long.valueOf(certData.get("id").toString());
        assertThat(certData.get("status").toString()).isEqualTo("ISSUED");

        ResponseEntity<Map> cert = rest.exchange("/api/certificates/" + certId, HttpMethod.GET,
                new HttpEntity<>(auth("requester", "requester123")), Map.class);
        assertThat(cert.getBody().get("status").toString()).isEqualTo("ISSUED");
        assertThat(cert.getBody().get("privateKeyAvailable")).isEqualTo(Boolean.TRUE);
        ResponseEntity<String> key = rest.exchange("/api/certificates/" + certId + "/key", HttpMethod.GET,
                new HttpEntity<>(auth("requester", "requester123")), String.class);
        assertThat(key.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(key.getBody()).contains("PRIVATE KEY");

        // cleanup
        rest.exchange("/api/profiles/" + profileId, HttpMethod.DELETE,
                new HttpEntity<>(auth("admin", "admin123")), Map.class);
        rest.exchange("/api/profiles/" + p11ProfileId, HttpMethod.DELETE,
                new HttpEntity<>(auth("admin", "admin123")), Map.class);
    }

    @Test
    void t13_moreKeyAlgorithms() throws Exception {
        // EC P-384 profile issues a certificate on the P-384 curve immediately
        Map<String, Object> ecBody = profileBody("EC P-384 Profile");
        ecBody.put("keyAlgorithm", "EC");
        ecBody.put("keySize", 384);
        ResponseEntity<Map> ecCreated = rest.exchange("/api/profiles", HttpMethod.POST,
                new HttpEntity<>(ecBody, auth("admin", "admin123")), Map.class);
        assertThat(ecCreated.getStatusCode()).isEqualTo(HttpStatus.OK);
        Map<?, ?> ecData = (Map<?, ?>) ecCreated.getBody().get("data");
        assertThat(ecData.get("keyAlgorithm").toString()).isEqualTo("EC");
        assertThat(Integer.valueOf(ecData.get("keySize").toString())).isEqualTo(384);
        Long ecProfileId = Long.valueOf(ecData.get("id").toString());

        Map<String, Object> ecReq = baseRequest("ec-p384.example.com");
        ecReq.put("profileId", ecProfileId);
        ResponseEntity<Map> ecSubmitted = rest.exchange("/api/certificates/request", HttpMethod.POST,
                new HttpEntity<>(ecReq, auth("requester", "requester123")), Map.class);
        assertThat(ecSubmitted.getStatusCode()).isEqualTo(HttpStatus.OK);
        Long ecCertId = Long.valueOf(((Map<?, ?>) ecSubmitted.getBody().get("data")).get("id").toString());
        assertThat(((Map<?, ?>) ecSubmitted.getBody().get("data")).get("status").toString()).isEqualTo("ISSUED");

        ResponseEntity<Map> ecCert = rest.exchange("/api/certificates/" + ecCertId, HttpMethod.GET,
                new HttpEntity<>(auth("requester", "requester123")), Map.class);
        assertThat(ecCert.getBody().get("status").toString()).isEqualTo("ISSUED");
        assertThat(ecCert.getBody().get("keyAlgorithm").toString()).isEqualTo("EC");
        assertThat(Integer.valueOf(ecCert.getBody().get("keySize").toString())).isEqualTo(384);
        X509Certificate ecLeaf = parseCert((String) ecCert.getBody().get("certificatePem"));
        assertThat(ecLeaf.getPublicKey().getAlgorithm()).isEqualTo("EC");
        assertThat(((java.security.interfaces.ECPublicKey) ecLeaf.getPublicKey())
                .getParams().getCurve().getField().getFieldSize()).isEqualTo(384);
        ecLeaf.verify(getIssuerCert().getPublicKey());

        // Ed25519 profile: fixed 256-bit key, download happens via PKCS#8 PEM
        Map<String, Object> edBody = profileBody("Ed25519 Profile");
        edBody.put("keyAlgorithm", "ED25519");
        edBody.put("keySize", 256);
        ResponseEntity<Map> edCreated = rest.exchange("/api/profiles", HttpMethod.POST,
                new HttpEntity<>(edBody, auth("admin", "admin123")), Map.class);
        assertThat(edCreated.getStatusCode()).isEqualTo(HttpStatus.OK);
        Long edProfileId = Long.valueOf(((Map<?, ?>) edCreated.getBody().get("data")).get("id").toString());

        Map<String, Object> edReq = baseRequest("ed25519.example.com");
        edReq.put("profileId", edProfileId);
        ResponseEntity<Map> edSubmitted = rest.exchange("/api/certificates/request", HttpMethod.POST,
                new HttpEntity<>(edReq, auth("requester", "requester123")), Map.class);
        assertThat(edSubmitted.getStatusCode()).isEqualTo(HttpStatus.OK);
        Long edCertId = Long.valueOf(((Map<?, ?>) edSubmitted.getBody().get("data")).get("id").toString());
        assertThat(((Map<?, ?>) edSubmitted.getBody().get("data")).get("status").toString()).isEqualTo("ISSUED");

        ResponseEntity<Map> edCert = rest.exchange("/api/certificates/" + edCertId, HttpMethod.GET,
                new HttpEntity<>(auth("requester", "requester123")), Map.class);
        assertThat(edCert.getBody().get("status").toString()).isEqualTo("ISSUED");
        assertThat(edCert.getBody().get("keyAlgorithm").toString()).isEqualTo("ED25519");
        ResponseEntity<String> edKey = rest.exchange("/api/certificates/" + edCertId + "/key", HttpMethod.GET,
                new HttpEntity<>(auth("requester", "requester123")), String.class);
        assertThat(edKey.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(edKey.getBody()).contains("PRIVATE KEY");
        X509Certificate edLeaf = parseCert((String) edCert.getBody().get("certificatePem"));
        assertThat(edLeaf.getPublicKey().getAlgorithm()).isEqualTo("Ed25519");
        edLeaf.verify(getIssuerCert().getPublicKey());

        // unsupported key size for EC is rejected
        Map<String, Object> badEc = baseRequest("bad-ec.example.com");
        badEc.put("keyAlgorithm", "EC");
        badEc.put("keySize", 2048);
        ResponseEntity<Map> badResp = rest.exchange("/api/certificates/request", HttpMethod.POST,
                new HttpEntity<>(badEc, auth("requester", "requester123")), Map.class);
        assertThat(badResp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

        // an EC (P-384) intermediate CA is created immediately and signs a leaf with ECDSA
        Map<String, Object> caBody = new LinkedHashMap<>();
        caBody.put("name", "EC Intermediate CA");
        caBody.put("subjectDn", "CN=EC Intermediate CA, O=Test, C=US");
        caBody.put("caType", "INTERMEDIATE");
        caBody.put("parentCaId", 1);
        caBody.put("keyAlgorithm", "EC");
        caBody.put("keySize", 384);
        caBody.put("validityDays", 365);
        caBody.put("requestedBy", "admin");
        ResponseEntity<Map> caCreated = rest.exchange("/api/ca", HttpMethod.POST,
                new HttpEntity<>(caBody, auth("admin", "admin123")), Map.class);
        assertThat(caCreated.getStatusCode()).isEqualTo(HttpStatus.OK);
        Long caId = Long.valueOf(((Map<?, ?>) caCreated.getBody().get("data")).get("id").toString());
        assertThat(((Map<?, ?>) caCreated.getBody().get("data")).get("status").toString()).isEqualTo("ISSUED");
        ResponseEntity<Map> ca = rest.exchange("/api/ca/" + caId, HttpMethod.GET,
                new HttpEntity<>(auth("admin", "admin123")), Map.class);
        assertThat(ca.getBody().get("status").toString()).isEqualTo("ISSUED");
        assertThat(ca.getBody().get("keyAlgorithm").toString()).isEqualTo("EC");
        assertThat(ca.getBody().get("signatureAlgorithm").toString()).isEqualTo("SHA384withECDSA");
        X509Certificate caCert = parseCert((String) ca.getBody().get("certificatePem"));
        assertThat(caCert.getPublicKey().getAlgorithm()).isEqualTo("EC");

        Map<String, Object> leafReq = baseRequest("ec-signed.example.com");
        leafReq.put("issuerCaId", caId);
        ResponseEntity<Map> leafSubmitted = rest.exchange("/api/certificates/request", HttpMethod.POST,
                new HttpEntity<>(leafReq, auth("requester", "requester123")), Map.class);
        assertThat(leafSubmitted.getStatusCode()).isEqualTo(HttpStatus.OK);
        Long leafId = Long.valueOf(((Map<?, ?>) leafSubmitted.getBody().get("data")).get("id").toString());
        assertThat(((Map<?, ?>) leafSubmitted.getBody().get("data")).get("status").toString()).isEqualTo("ISSUED");
        ResponseEntity<Map> leaf = rest.exchange("/api/certificates/" + leafId, HttpMethod.GET,
                new HttpEntity<>(auth("requester", "requester123")), Map.class);
        assertThat(leaf.getBody().get("status").toString()).isEqualTo("ISSUED");
        X509Certificate leafCert = parseCert((String) leaf.getBody().get("certificatePem"));
        leafCert.verify(caCert.getPublicKey());

        // cleanup
        rest.exchange("/api/profiles/" + ecProfileId, HttpMethod.DELETE,
                new HttpEntity<>(auth("admin", "admin123")), Map.class);
        rest.exchange("/api/profiles/" + edProfileId, HttpMethod.DELETE,
                new HttpEntity<>(auth("admin", "admin123")), Map.class);
    }

    @Test
    void t14_oidCatalog() {
        // any authenticated user (including a requester) can read the OID catalog
        ResponseEntity<List> oids = rest.exchange("/api/crypto/oids", HttpMethod.GET,
                new HttpEntity<>(auth("requester", "requester123")), List.class);
        assertThat(oids.getStatusCode()).isEqualTo(HttpStatus.OK);
        List<?> catalog = oids.getBody();
        assertThat(catalog).isNotEmpty();

        Map<?, ?> san = null;
        for (Object o : catalog) {
            Map<String, Object> entry = (Map<String, Object>) o;
            assertThat(entry).containsKeys("oid", "label", "type");
            assertThat(entry.get("type")).isIn("STRING", "INTEGER", "BOOLEAN", "OCTETS");
            if ("2.5.29.17".equals(entry.get("oid"))) {
                san = entry;
            }
        }
        assertThat(san).isNotNull();
        assertThat(san.get("label")).isNotNull();
    }

    @Test
    void t15_systemManagedOrDuplicateOids() throws Exception {
        // a system-managed OID (Key Usage) cannot be added as a custom extension
        Map<String, Object> kuBody = baseRequest("managed-oid.example.com");
        kuBody.put("additionalExtensions", List.of(
                Map.of("oid", "2.5.29.15", "type", "STRING", "value", "digitalSignature")));
        ResponseEntity<Map> kuRejected = rest.exchange("/api/certificates/request", HttpMethod.POST,
                new HttpEntity<>(kuBody, auth("requester", "requester123")), Map.class);
        assertThat(kuRejected.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

        // a system-managed OID (Subject Alternative Name) cannot be added as a custom extension
        Map<String, Object> sanBody = baseRequest("managed-san.example.com");
        sanBody.put("additionalExtensions", List.of(
                Map.of("oid", "2.5.29.17", "type", "STRING", "value", "san.example.com")));
        ResponseEntity<Map> sanRejected = rest.exchange("/api/certificates/request", HttpMethod.POST,
                new HttpEntity<>(sanBody, auth("requester", "requester123")), Map.class);
        assertThat(sanRejected.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

        // a duplicate custom OID is rejected with a clear message
        Map<String, Object> dupBody = baseRequest("dup-oid.example.com");
        dupBody.put("additionalExtensions", List.of(
                Map.of("oid", "1.2.3.4.5.6.7.9", "type", "STRING", "value", "one"),
                Map.of("oid", "1.2.3.4.5.6.7.9", "type", "STRING", "value", "two")));
        ResponseEntity<Map> dupRejected = rest.exchange("/api/certificates/request", HttpMethod.POST,
                new HttpEntity<>(dupBody, auth("requester", "requester123")), Map.class);
        assertThat(dupRejected.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(dupRejected.getBody().get("message").toString()).contains("more than once");

        // a valid custom extension still issues fine
        Map<String, Object> goodBody = baseRequest("good-oid.example.com");
        goodBody.put("additionalExtensions", List.of(
                Map.of("oid", "1.2.3.4.5.6.7.10", "type", "STRING", "value", "ok")));
        ResponseEntity<Map> good = rest.exchange("/api/certificates/request", HttpMethod.POST,
                new HttpEntity<>(goodBody, auth("requester", "requester123")), Map.class);
        assertThat(good.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(((Map<?, ?>) good.getBody().get("data")).get("status").toString()).isEqualTo("ISSUED");
    }

    @Test
    void t16_signedAuditLog() {
        // the audit log is admin-only
        ResponseEntity<Map> forbidden = rest.exchange("/api/audit", HttpMethod.GET,
                new HttpEntity<>(auth("requester", "requester123")), Map.class);
        assertThat(forbidden.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

        // a failed HTTP Basic login is audited with the attempted username
        rest.exchange("/api/ca", HttpMethod.POST,
                new HttpEntity<>(Map.of("name", "x"), auth("admin", "wrong-password")), Map.class);

        // admin sees the full chain: entries linked via prevHash and 64-char hashes/signatures
        ResponseEntity<List> listed = rest.exchange("/api/audit", HttpMethod.GET,
                new HttpEntity<>(auth("admin", "admin123")), List.class);
        assertThat(listed.getStatusCode()).isEqualTo(HttpStatus.OK);
        List<?> entries = listed.getBody();
        assertThat(entries).isNotEmpty();

        List<Map<?, ?>> maps = new java.util.ArrayList<>();
        for (Object o : entries) {
            maps.add((Map<?, ?>) o);
        }
        List<Map<?, ?>> adminLoginFailures = maps.stream()
                .filter(e -> "LOGIN_FAILED".equals(e.get("action")) && "admin".equals(e.get("actor")))
                .toList();
        assertThat(adminLoginFailures).hasSize(1);

        String prevHash = "";
        for (Object o : entries) {
            Map<?, ?> e = (Map<?, ?>) o;
            assertThat(e.get("hash").toString()).hasSize(64);
            assertThat(e.get("signature").toString()).hasSize(64);
            assertThat(e.get("prevHash").toString()).isEqualTo(prevHash);
            prevHash = e.get("hash").toString();
        }

        // the whole chain verifies as intact (hash + HMAC recomputed from scratch)
        ResponseEntity<Map> verified = rest.exchange("/api/audit/verify", HttpMethod.GET,
                new HttpEntity<>(auth("admin", "admin123")), Map.class);
        assertThat(verified.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(Boolean.TRUE.equals(verified.getBody().get("valid"))).isTrue();
        assertThat(((Number) verified.getBody().get("total")).longValue()).isEqualTo(entries.size());
        assertThat(((Number) verified.getBody().get("verified")).longValue()).isEqualTo(entries.size());

        // tampering with any stored field breaks the chain and is detected
        AuditLog last = auditLogRepository.findTopByOrderByIdDesc().orElseThrow();
        last.setDetail("tampered by integration test");
        auditLogRepository.save(last);

        ResponseEntity<Map> tampered = rest.exchange("/api/audit/verify", HttpMethod.GET,
                new HttpEntity<>(auth("admin", "admin123")), Map.class);
        assertThat(Boolean.TRUE.equals(tampered.getBody().get("valid"))).isFalse();
        assertThat(tampered.getBody().get("failedAt")).isNotNull();
        assertThat(tampered.getBody().get("message").toString()).contains("broken");
    }

    @Test
    void t17_searchAndViewCertificatesByAnyRole() {
        // requester issues two certificates, admin issues one (owned by admin)
        Map<String, Object> alpha = baseRequest("alpha-search.example.com");
        Map<String, Object> beta = baseRequest("beta-search.example.com");
        ResponseEntity<Map> alphaResp = rest.exchange("/api/certificates/request", HttpMethod.POST,
                new HttpEntity<>(alpha, auth("requester", "requester123")), Map.class);
        assertThat(alphaResp.getStatusCode()).isEqualTo(HttpStatus.OK);
        Long alphaId = Long.valueOf(((Map<?, ?>) alphaResp.getBody().get("data")).get("id").toString());
        ResponseEntity<Map> betaResp = rest.exchange("/api/certificates/request", HttpMethod.POST,
                new HttpEntity<>(beta, auth("requester", "requester123")), Map.class);
        Long betaId = Long.valueOf(((Map<?, ?>) betaResp.getBody().get("data")).get("id").toString());

        Map<String, Object> adminCert = baseRequest("admin-owned.example.com");
        adminCert.put("requestedBy", "admin");
        ResponseEntity<Map> adminResp = rest.exchange("/api/certificates/request", HttpMethod.POST,
                new HttpEntity<>(adminCert, auth("admin", "admin123")), Map.class);
        assertThat(adminResp.getStatusCode()).isEqualTo(HttpStatus.OK);
        Long adminCertId = Long.valueOf(((Map<?, ?>) adminResp.getBody().get("data")).get("id").toString());

        // both roles can search across ALL certificates by common name (case-insensitive)
        for (String[] who : new String[][]{{"requester", "requester123"}, {"admin", "admin123"}}) {
            ResponseEntity<List> byName = rest.exchange("/api/certificates?q=ALPHA-SEARCH", HttpMethod.GET,
                    new HttpEntity<>(auth(who[0], who[1])), List.class);
            assertThat(byName.getStatusCode()).isEqualTo(HttpStatus.OK);
            List<?> found = byName.getBody();
            assertThat(found).isNotEmpty();
            assertThat(((Map<?, ?>) found.get(0)).get("id").toString()).isEqualTo(alphaId.toString());
        }

        // search by serial (substring), requester included
        ResponseEntity<Map> cert = rest.exchange("/api/certificates/" + alphaId, HttpMethod.GET,
                new HttpEntity<>(auth("requester", "requester123")), Map.class);
        String serial = cert.getBody().get("serialNumber").toString();
        String serialFrag = serial.substring(0, Math.min(6, serial.length()));
        ResponseEntity<List> bySerial = rest.exchange(
                "/api/certificates?q=" + serialFrag, HttpMethod.GET,
                new HttpEntity<>(auth("requester", "requester123")), List.class);
        assertThat(bySerial.getBody()).isNotEmpty();

        // search by requester name finds the requester's certs for both roles
        ResponseEntity<List> byOwner = rest.exchange("/api/certificates?q=requester", HttpMethod.GET,
                new HttpEntity<>(auth("admin", "admin123")), List.class);
        List<?> ownerHits = byOwner.getBody();
        assertThat(ownerHits.stream()
                .map(o -> ((Map<?, ?>) o).get("id").toString()))
                .contains(alphaId.toString(), betaId.toString());

        // combine a status filter with the search term
        ResponseEntity<List> byStatus = rest.exchange("/api/certificates?q=search&status=ISSUED", HttpMethod.GET,
                new HttpEntity<>(auth("requester", "requester123")), List.class);
        assertThat(byStatus.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(byStatus.getBody()).isNotEmpty();

        // a requester can VIEW any certificate, including one requested by an admin
        ResponseEntity<Map> viewOther = rest.exchange("/api/certificates/" + adminCertId, HttpMethod.GET,
                new HttpEntity<>(auth("requester", "requester123")), Map.class);
        assertThat(viewOther.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(viewOther.getBody().get("commonName").toString()).isEqualTo("admin-owned.example.com");
        assertThat(viewOther.getBody().get("requestedBy").toString()).isEqualTo("admin");

        // an admin can VIEW a requester's certificate the same way
        ResponseEntity<Map> viewAsAdmin = rest.exchange("/api/certificates/" + betaId, HttpMethod.GET,
                new HttpEntity<>(auth("admin", "admin123")), Map.class);
        assertThat(viewAsAdmin.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(viewAsAdmin.getBody().get("commonName").toString()).isEqualTo("beta-search.example.com");

        // but the private key stays owner-only (requester cannot fetch the admin's key)
        ResponseEntity<String> keyForbidden = rest.exchange("/api/certificates/" + adminCertId + "/key", HttpMethod.GET,
                new HttpEntity<>(auth("requester", "requester123")), String.class);
        assertThat(keyForbidden.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void t18_userManagement() {
        // user management is admin-only
        ResponseEntity<Map> forbidden = rest.exchange("/api/users", HttpMethod.GET,
                new HttpEntity<>(auth("requester", "requester123")), Map.class);
        assertThat(forbidden.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

        // admin sees the seeded accounts
        ResponseEntity<List> listed = rest.exchange("/api/users", HttpMethod.GET,
                new HttpEntity<>(auth("admin", "admin123")), List.class);
        assertThat(listed.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(listed.getBody()).hasSize(2);

        // admin creates a new requester user
        Map<String, Object> create = Map.of("username", "alice", "password", "alice123", "admin", false);
        ResponseEntity<Map> created = rest.exchange("/api/users", HttpMethod.POST,
                new HttpEntity<>(create, auth("admin", "admin123")), Map.class);
        assertThat(created.getStatusCode()).isEqualTo(HttpStatus.OK);
        Map<?, ?> userData = (Map<?, ?>) created.getBody().get("data");
        Long aliceId = Long.valueOf(userData.get("id").toString());
        assertThat(userData.get("username").toString()).isEqualTo("alice");

        // duplicate usernames are rejected
        ResponseEntity<Map> duplicate = rest.exchange("/api/users", HttpMethod.POST,
                new HttpEntity<>(create, auth("admin", "admin123")), Map.class);
        assertThat(duplicate.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

        // alice can log in but is not an admin and cannot manage users
        ResponseEntity<Map> aliceMe = rest.exchange("/api/me", HttpMethod.GET,
                new HttpEntity<>(auth("alice", "alice123")), Map.class);
        assertThat(aliceMe.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(aliceMe.getBody().get("roles").toString()).doesNotContain("ADMIN");
        ResponseEntity<Map> aliceForbidden = rest.exchange("/api/users", HttpMethod.GET,
                new HttpEntity<>(auth("alice", "alice123")), Map.class);
        assertThat(aliceForbidden.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

        // admin promotes alice to administrator; alice can now manage users
        ResponseEntity<Map> promoted = rest.exchange("/api/users/" + aliceId, HttpMethod.PUT,
                new HttpEntity<>(Map.of("admin", true), auth("admin", "admin123")), Map.class);
        assertThat(promoted.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(((Map<?, ?>) promoted.getBody().get("data")).get("roles").toString()).contains("ADMIN");
        ResponseEntity<List> aliceList = rest.exchange("/api/users", HttpMethod.GET,
                new HttpEntity<>(auth("alice", "alice123")), List.class);
        assertThat(aliceList.getStatusCode()).isEqualTo(HttpStatus.OK);

        // admin can also demote alice again
        rest.exchange("/api/users/" + aliceId, HttpMethod.PUT,
                new HttpEntity<>(Map.of("admin", false), auth("admin", "admin123")), Map.class);

        // disabling alice prevents her from authenticating at all (401)
        rest.exchange("/api/users/" + aliceId, HttpMethod.PUT,
                new HttpEntity<>(Map.of("enabled", false), auth("admin", "admin123")), Map.class);
        ResponseEntity<Map> disabled = rest.exchange("/api/me", HttpMethod.GET,
                new HttpEntity<>(auth("alice", "alice123")), Map.class);
        assertThat(disabled.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        // re-enable and reset her password; the new password works, the old one does not
        rest.exchange("/api/users/" + aliceId, HttpMethod.PUT,
                new HttpEntity<>(Map.of("enabled", true), auth("admin", "admin123")), Map.class);
        ResponseEntity<Map> reset = rest.exchange("/api/users/" + aliceId + "/password", HttpMethod.PUT,
                new HttpEntity<>(Map.of("password", "newpass456"), auth("admin", "admin123")), Map.class);
        assertThat(reset.getStatusCode()).isEqualTo(HttpStatus.OK);
        ResponseEntity<Map> oldLogin = rest.exchange("/api/me", HttpMethod.GET,
                new HttpEntity<>(auth("alice", "alice123")), Map.class);
        assertThat(oldLogin.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        ResponseEntity<Map> newLogin = rest.exchange("/api/me", HttpMethod.GET,
                new HttpEntity<>(auth("alice", "newpass456")), Map.class);
        assertThat(newLogin.getStatusCode()).isEqualTo(HttpStatus.OK);

        // guards: admin cannot demote, disable or delete their own account
        ResponseEntity<Map> selfDemote = rest.exchange("/api/users/1", HttpMethod.PUT,
                new HttpEntity<>(Map.of("admin", false), auth("admin", "admin123")), Map.class);
        assertThat(selfDemote.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        ResponseEntity<Map> selfDisable = rest.exchange("/api/users/1", HttpMethod.PUT,
                new HttpEntity<>(Map.of("enabled", false), auth("admin", "admin123")), Map.class);
        assertThat(selfDisable.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        ResponseEntity<Map> selfDelete = rest.exchange("/api/users/1", HttpMethod.DELETE,
                new HttpEntity<>(auth("admin", "admin123")), Map.class);
        assertThat(selfDelete.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

        // cleanup: admin deletes alice
        ResponseEntity<Map> deleted = rest.exchange("/api/users/" + aliceId, HttpMethod.DELETE,
                new HttpEntity<>(auth("admin", "admin123")), Map.class);
        assertThat(deleted.getStatusCode()).isEqualTo(HttpStatus.OK);
        ResponseEntity<Map> aliceGone = rest.exchange("/api/me", HttpMethod.GET,
                new HttpEntity<>(auth("alice", "newpass456")), Map.class);
        assertThat(aliceGone.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    private Map<?, ?> findProfile(List<?> profiles, String name) {
        for (Object o : profiles) {
            Map<?, ?> p = (Map<?, ?>) o;
            if (name.equals(p.get("name"))) {
                return p;
            }
        }
        return null;
    }

    private Map<String, Object> profileBody(String name) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("name", name);
        body.put("description", "Created by integration test");
        body.put("keyAlgorithm", "RSA");
        body.put("keySize", 2048);
        body.put("validityDays", 365);
        body.put("caProfile", false);
        body.put("keyUsage", List.of("digitalSignature", "keyEncipherment"));
        body.put("extendedKeyUsage", List.of("serverAuth"));
        return body;
    }

    private Map<String, Object> baseRequest(String commonName) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("commonName", commonName);
        body.put("issuerCaId", 2);
        body.put("requestedBy", "requester");
        return body;
    }

    private org.bouncycastle.cert.X509CertificateHolder certHolder(String certPem) throws Exception {
        try (StringReader sr = new StringReader(certPem);
             org.bouncycastle.openssl.PEMParser parser = new org.bouncycastle.openssl.PEMParser(sr)) {
            return (org.bouncycastle.cert.X509CertificateHolder) parser.readObject();
        }
    }

    private List<String> sansOf(String certPem) throws Exception {
        try (StringReader sr = new StringReader(certPem);
             org.bouncycastle.openssl.PEMParser parser = new org.bouncycastle.openssl.PEMParser(sr)) {
            org.bouncycastle.cert.X509CertificateHolder holder =
                    (org.bouncycastle.cert.X509CertificateHolder) parser.readObject();
            Extension san = holder.getExtension(Extension.subjectAlternativeName);
            List<String> result = new java.util.ArrayList<>();
            if (san != null) {
                for (GeneralName name : GeneralNames.getInstance(san.getParsedValue()).getNames()) {
                    if (name.getTagNo() == GeneralName.dNSName) {
                        result.add(org.bouncycastle.asn1.DERIA5String.getInstance(name.getName()).getString());
                    } else if (name.getTagNo() == GeneralName.iPAddress) {
                        byte[] bytes = org.bouncycastle.asn1.ASN1OctetString.getInstance(name.getName()).getOctets();
                        result.add(java.net.InetAddress.getByAddress(bytes).getHostAddress());
                    } else {
                        result.add(name.getName().toString());
                    }
                }
            }
            return result;
        }
    }

    private KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private String generateCsr(KeyPair kp, String subject) throws Exception {
        JcaPKCS10CertificationRequestBuilder csrBuilder =
                new JcaPKCS10CertificationRequestBuilder(new X500Name(subject), kp.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        PKCS10CertificationRequest csr = csrBuilder.build(signer);
        StringWriter sw = new StringWriter();
        try (org.bouncycastle.openssl.jcajce.JcaPEMWriter writer =
                     new org.bouncycastle.openssl.jcajce.JcaPEMWriter(sw)) {
            writer.writeObject(csr);
        }
        return sw.toString();
    }

    private X509Certificate getIssuerCert() throws Exception {
        // issuer is the intermediate CA (id 2) seeded by DataSeeder
        ResponseEntity<Map> ca = rest.exchange("/api/ca/2", HttpMethod.GET,
                new HttpEntity<>(auth("admin", "admin123")), Map.class);
        String caPem = (String) ca.getBody().get("certificatePem");
        return parseCert(caPem);
    }

    private X509Certificate parseCert(String certPem) throws Exception {
        try (StringReader sr = new StringReader(certPem);
             org.bouncycastle.openssl.PEMParser parser = new org.bouncycastle.openssl.PEMParser(sr)) {
            org.bouncycastle.cert.X509CertificateHolder holder =
                    (org.bouncycastle.cert.X509CertificateHolder) parser.readObject();
            return new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(holder);
        }
    }

    private byte[] buildOcspRequest(X509Certificate issuerCert, BigInteger serial) throws Exception {
        CertificateID certId = new JcaCertificateID(
                new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
                issuerCert, serial);
        OCSPReqBuilder reqGen = new OCSPReqBuilder();
        reqGen.addRequest(certId);
        OCSPReq req = reqGen.build();
        return req.getEncoded();
    }
}
