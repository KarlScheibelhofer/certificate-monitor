package dev.scheibelhofer.certificate.monitor;

import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.List;

import javax.ws.rs.core.MediaType;

import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.path.json.JsonPath;

@QuarkusTest
@TestMethodOrder(OrderAnnotation.class)
public class CertificateResourceTest {

    @Test
    @Order(1)
    public void testGetEmptyCertificates() {
        given()
          .when().get("/certificates")
          .then()
             .statusCode(200)
             .body("$.size()", is(0));
    }

    @Test
    @Order(2)
    public void testPostGetDelete() throws Exception {
        CertFile certFile = CertFile.parse("google.com.crt");

    	String id =
	        given()
                .contentType(MediaType.TEXT_PLAIN)
                .body(certFile.getPemEncodedCertificate())
	        .when()
	            .post("/certificates")
	        .then()
	            .statusCode(201)
	            .body("subjectDN", is(certFile.getCertificate().getSubjectX500Principal().getName()))
	            .body("issuerDN", is(certFile.getCertificate().getIssuerX500Principal().getName()))
	            .body("serial", is(certFile.getCertificate().getSerialNumber().toString(16)))
                .body("pemEncoded", startsWith("-----BEGIN CERTIFICATE-----\r\n"))
                .body("pemEncoded", endsWith("-----END CERTIFICATE-----\r\n"))
                .body("validNotAfter", equalTo(certFile.getCertificate().getNotAfter().toInstant().toString()))
                .body("validNotBefore", equalTo(certFile.getCertificate().getNotBefore().toInstant().toString()))
                .extract()
            	.path("id");

        assertNotNull(id, "id is null");
        assertThat("id must be 64 characters", Integer.valueOf(id.length()), equalTo(Integer.valueOf(64)));
        assertThat(id, equalTo(certFile.getSha256fingerprint()));

        given()
            .when()
                .get("/certificates/{id}", id)
            .then()
                .statusCode(200)
                .body("subjectDN", is(certFile.getCertificate().getSubjectX500Principal().getName()))
                .body("issuerDN", is(certFile.getCertificate().getIssuerX500Principal().getName()))
                .body("serial", is(certFile.getCertificate().getSerialNumber().toString(16)))
                .body("pemEncoded", startsWith("-----BEGIN CERTIFICATE-----\r\n"))
                .body("pemEncoded", endsWith("-----END CERTIFICATE-----\r\n"))
                .body("validNotAfter", equalTo(certFile.getCertificate().getNotAfter().toInstant().toString()))
                .body("validNotBefore", equalTo(certFile.getCertificate().getNotBefore().toInstant().toString()))
                   ;

        given()
	        .when()
	            .delete("/certificates/{id}", id)
	        .then()
	            .statusCode(204);
    }

    @Test
    @Order(3)
    public void testPostCertificateMultiple() throws Exception {
        CertFile certFile = CertFile.parse("orf.at.crt");

    	String id =
	        given()
                .contentType(MediaType.TEXT_PLAIN)
                .body(certFile.getPemEncodedCertificate())
	        .when()
	            .post("/certificates")
	        .then()
	            .statusCode(201)
	            .body("subjectDN", is(certFile.getCertificate().getSubjectX500Principal().getName()))
	            .body("issuerDN", is(certFile.getCertificate().getIssuerX500Principal().getName()))
	            .body("serial", is(certFile.getCertificate().getSerialNumber().toString(16)))
	        .extract()
            	.path("id");


        String id2 =
            given()
                .contentType(MediaType.TEXT_PLAIN)
                .body(certFile.getPemEncodedCertificate())
            .when()
                .post("/certificates")
            .then()
                .statusCode(200)
                .body("subjectDN", is(certFile.getCertificate().getSubjectX500Principal().getName()))
                .body("issuerDN", is(certFile.getCertificate().getIssuerX500Principal().getName()))
	            .body("serial", is(certFile.getCertificate().getSerialNumber().toString(16)))
            .extract()
                .path("id");

        assertThat(id2, equalTo(id));

        given()
	        .when()
	            .delete("/certificates/{id}", id)
	        .then()
	            .statusCode(204);
    }

    @Test
    @Order(4)
    public void testFindBySubject() throws Exception {
        CertFile gitHubCertFile = CertFile.parse("github.com.crt");
    	String idGitHub =
	        given()
                .body(gitHubCertFile.getPemEncodedCertificate())
	        .when()
	            .post("/certificates")
	        .then()
	            .statusCode(201)
	        .extract()
            	.path("id");

        CertFile microsoftCertFile = CertFile.parse("www.microsoft.com.crt");
    	String idMicrosoft =
	        given()
                .body(microsoftCertFile.getPemEncodedCertificate())
	        .when()
	            .post("/certificates")
	        .then()
	            .statusCode(201)
	        .extract()
            	.path("id");

        // search for github.com
    	JsonPath responseJsonGithub = given()
            .when()
                .queryParam("subject", "github.com")
                .get("/certificates")
            .then()
                .statusCode(200)
                .extract().body().jsonPath();

        List<Certificate> githubCertList = responseJsonGithub.getList("", Certificate.class);

        assertThat(githubCertList.size(), equalTo(1));
        Certificate githubCert = githubCertList.get(0);
        assertThat(githubCert.id, equalTo(idGitHub));

        // search for microsoft.com
    	JsonPath responseJsonMicrosoft = given()
            .when()
                .queryParam("subject", "microsoft.com")
                .get("/certificates")
            .then()
                .statusCode(200)
                .extract().body().jsonPath();

        List<Certificate> microsoftCertList = responseJsonMicrosoft.getList("", Certificate.class);

        assertThat(microsoftCertList.size(), equalTo(1));
        Certificate microsoftCert = microsoftCertList.get(0);
        assertThat(microsoftCert.id, equalTo(idMicrosoft));

        given().when().delete("/certificates/{id}", idGitHub).then().statusCode(204);
        given().when().delete("/certificates/{id}", idMicrosoft).then().statusCode(204);
    }

    @Test
    @Order(5)
    public void testFindByDNSName() throws Exception {
        CertFile gitHubCertFile = CertFile.parse("github.com.crt");
    	String idGitHub =
	        given()
                .body(gitHubCertFile.getPemEncodedCertificate())
	        .when()
	            .post("/certificates")
	        .then()
	            .statusCode(201)
	        .extract()
            	.path("id");

        CertFile microsoftCertFile = CertFile.parse("www.microsoft.com.crt");
    	String idMicrosoft =
	        given()
                .body(microsoftCertFile.getPemEncodedCertificate())
	        .when()
	            .post("/certificates")
	        .then()
	            .statusCode(201)
	        .extract()
            	.path("id");

        // search for www.github.com
    	List<Certificate> githubCertList = given()
            .when()
                .queryParam("dns", "www.github.com")
                .get("/certificates")
            .then()
                .statusCode(200)
            .extract().body().jsonPath().getList("", Certificate.class);

        assertThat(githubCertList.size(), equalTo(1));
        Certificate githubCert = githubCertList.get(0);
        assertThat(githubCert.id, equalTo(idGitHub));

        // search for privacy.microsoft.com
    	List<Certificate> microsoftCertList = given()
            .when()
                .queryParam("dns", "privacy.microsoft.com")
                .get("/certificates")
            .then()
                .statusCode(200)
            .extract().body().jsonPath().getList("", Certificate.class);

        assertThat(microsoftCertList.size(), equalTo(1));
        Certificate microsoftCert = microsoftCertList.get(0);
        assertThat(microsoftCert.id, equalTo(idMicrosoft));

        given().when().delete("/certificates/{id}", idGitHub).then().statusCode(204);
        given().when().delete("/certificates/{id}", idMicrosoft).then().statusCode(204);
    }

}