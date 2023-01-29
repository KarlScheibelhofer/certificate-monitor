package dev.scheibelhofer.certificate.monitor;

import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;
import static org.hamcrest.Matchers.endsWith;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.HexFormat;

import javax.ws.rs.core.MediaType;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;

@QuarkusTest
public class CertificateResourceTest {

    @Test
    public void testHelloEndpoint() {
        given()
          .when().get("/certificates")
          .then()
             .statusCode(200)
             .body(is("Hello RESTEasy"));
    }

    @Test
    public void testCertificateCreate() throws Exception {
        String fileName = "google.com.crt";
        byte[] pemEncodedCertificate = getClass().getClassLoader().getResourceAsStream(fileName).readAllBytes();
        X509Certificate certificate = Utils.parseCertificate(pemEncodedCertificate);
        
    	String id = 
	        given()
                .contentType(MediaType.TEXT_PLAIN)
                .body(pemEncodedCertificate)
	        .when()
	            .post("/certificates")
	        .then()
	            .statusCode(201)
	            .body("subjectDN", is(certificate.getSubjectX500Principal().getName()))
	            .body("issuerDN", is(certificate.getIssuerX500Principal().getName()))
                .body("pemEncoded", startsWith("-----BEGIN CERTIFICATE-----\r\n"))
                .body("pemEncoded", endsWith("-----END CERTIFICATE-----\r\n"))
                .body("validNotAfter", equalTo("2023-04-03T08:16:57"))
                .body("validNotBefore", equalTo("2023-01-09T08:16:58"))
	        .extract()
            	.path("id");

        assertNotNull(id, "id is null");
        assertThat("id must be 64 characters", Integer.valueOf(id.length()), equalTo(Integer.valueOf(64)));
        String sha256Fingerprint = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));
        assertThat(id, equalTo(sha256Fingerprint));

    	given()
	        .when()
	            .get("/certificates/{id}", id)
	        .then()
                .statusCode(200)
	            .body("subjectDN", is(certificate.getSubjectX500Principal().getName()))
	            .body("issuerDN", is(certificate.getIssuerX500Principal().getName()))
                .body("pemEncoded", startsWith("-----BEGIN CERTIFICATE-----\r\n"))
                .body("pemEncoded", endsWith("-----END CERTIFICATE-----\r\n"))
                .body("validNotAfter", equalTo("2023-04-03T08:16:57"))
                .body("validNotBefore", equalTo("2023-01-09T08:16:58"))
                ;             
    }

}