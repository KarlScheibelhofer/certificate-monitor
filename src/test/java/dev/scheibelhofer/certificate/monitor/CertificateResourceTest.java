package dev.scheibelhofer.certificate.monitor;

import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.stream.Collectors;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.path.json.JsonPath;

@QuarkusTest
@TestMethodOrder(OrderAnnotation.class)
public class CertificateResourceTest {

    @BeforeEach
    public void cleanup() {
        given()
        .when()
            .delete("/certificates")
        .then()
            .statusCode(Response.Status.NO_CONTENT.getStatusCode());
    }

    @Test
    @Order(1)
    public void testGetEmptyCertificates() {
        given()
          .when().get("/certificates")
          .then()
             .statusCode(Response.Status.OK.getStatusCode())
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
	            .statusCode(Response.Status.CREATED.getStatusCode())
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
                .statusCode(Response.Status.OK.getStatusCode())
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
	            .statusCode(Response.Status.NO_CONTENT.getStatusCode());
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
	            .statusCode(Response.Status.CREATED.getStatusCode())
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
                .statusCode(Response.Status.OK.getStatusCode())
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
	            .statusCode(Response.Status.NO_CONTENT.getStatusCode());
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
	            .statusCode(Response.Status.CREATED.getStatusCode())
	        .extract()
            	.path("id");

        CertFile microsoftCertFile = CertFile.parse("www.microsoft.com.crt");
    	String idMicrosoft =
	        given()
                .body(microsoftCertFile.getPemEncodedCertificate())
	        .when()
	            .post("/certificates")
	        .then()
	            .statusCode(Response.Status.CREATED.getStatusCode())
	        .extract()
            	.path("id");

        // search for github.com
    	JsonPath responseJsonGithub = given()
            .when()
                .queryParam("subject", "github.com")
                .get("/certificates")
            .then()
                .statusCode(Response.Status.OK.getStatusCode())
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
                .statusCode(Response.Status.OK.getStatusCode())
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
	            .statusCode(Response.Status.CREATED.getStatusCode())
	        .extract()
            	.path("id");

        CertFile microsoftCertFile = CertFile.parse("www.microsoft.com.crt");
    	String idMicrosoft =
	        given()
                .body(microsoftCertFile.getPemEncodedCertificate())
	        .when()
	            .post("/certificates")
	        .then()
	            .statusCode(Response.Status.CREATED.getStatusCode())
	        .extract()
            	.path("id");

        // search for www.github.com
    	List<Certificate> githubCertList = given()
            .when()
                .queryParam("dns", "www.github.com")
                .get("/certificates")
            .then()
                .statusCode(Response.Status.OK.getStatusCode())
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
                .statusCode(Response.Status.OK.getStatusCode())
            .extract().body().jsonPath().getList("", Certificate.class);

        assertThat(microsoftCertList.size(), equalTo(1));
        Certificate microsoftCert = microsoftCertList.get(0);
        assertThat(microsoftCert.id, equalTo(idMicrosoft));

        given().when().delete("/certificates/{id}", idGitHub).then().statusCode(204);
        given().when().delete("/certificates/{id}", idMicrosoft).then().statusCode(204);
    }

    CertFile postCertificate(String certFile, Integer expectedStatusCode) throws IOException, GeneralSecurityException {
        CertFile cert = CertFile.parse(certFile);
    	String id =
	        given()
                .body(cert.getPemEncodedCertificate())
	        .when()
	            .post("/certificates")
	        .then()
	            .statusCode(Response.Status.CREATED.getStatusCode())
	        .extract()
            	.path("id");
        assertThat(id, equalTo(cert.getSha256fingerprint()));                
        return cert;
    }

    @Test
    @Order(6)
    public void testListExpiringCerts() throws Exception {
        // ❯ for f in src/test/resources/*.crt; do echo -n "$f - "; openssl x509 -in $f -noout -enddate; done
        // src/test/resources/github.com.crt - notAfter=Mar 15 23:59:59 2023 GMT
        // src/test/resources/google.com.crt - notAfter=Apr  3 08:16:57 2023 GMT
        // src/test/resources/orf.at.crt - notAfter=Apr 22 12:03:50 2023 GMT
        // src/test/resources/www.microsoft.com.crt - notAfter=Sep 29 23:23:11 2023 GMT

        CertFile githubCertFile = postCertificate("github.com.crt", Response.Status.CREATED.getStatusCode());
        CertFile googleCertFile = postCertificate("google.com.crt", Response.Status.CREATED.getStatusCode());
        CertFile orfCertFile = postCertificate("orf.at.crt", Response.Status.CREATED.getStatusCode());
        CertFile microsoftCertFile = postCertificate("www.microsoft.com.crt", Response.Status.CREATED.getStatusCode());

        // search for certificates expiring in the next 90 days, specified as ISO-8601 period
    	List<Certificate> expiringCertList = given()
            .when()
                .queryParam("expiring", "P90D")
                .get("/certificates")
            .then()
                .statusCode(200)
            .extract().body().jsonPath().getList("", Certificate.class);

        assertThat(expiringCertList.size(), equalTo(3));
        assertThat(expiringCertList.get(0).id, equalTo(githubCertFile.getSha256fingerprint()));
        assertThat(expiringCertList.get(1).id, equalTo(googleCertFile.getSha256fingerprint()));
        assertThat(expiringCertList.get(2).id, equalTo(orfCertFile.getSha256fingerprint()));

    	String csvString = given().header("Accept", "text/csv")
            .when()
                .queryParam("expiring", "P90D")
                .get("/certificates")
            .then()
                .statusCode(200)
            .extract().body().asString();
        
        List<String> csvLines = csvString.lines().collect(Collectors.toList());
        String header = csvLines.remove(0);
        assertThat(header, equalTo("validNotAfter,dnsNames,subjectDN,issuerDN,serial,id,validNotBefore,pemEncoded"));
        String csvRegExp = "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z,(\\\"[^\\\"]*\\\"|[^,]*),(\\\"[^\\\"]*\\\"|[^,]*),(\\\"[^\\\"]*\\\"|[^,]*),[0-9a-f]*,[0-9a-f]*,\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z,-----BEGIN CERTIFICATE-----[0-9a-zA-Z+/=\\\\]*-----END CERTIFICATE-----(\\\\r\\\\n)*$";
        assertTrue(csvLines.stream().allMatch(
            s -> {
                return s.matches(csvRegExp);
            }));

        given().when().delete("/certificates/{id}", githubCertFile.getSha256fingerprint()).then().statusCode(204);
        given().when().delete("/certificates/{id}", googleCertFile.getSha256fingerprint()).then().statusCode(204);
        given().when().delete("/certificates/{id}", orfCertFile.getSha256fingerprint()).then().statusCode(204);
        given().when().delete("/certificates/{id}", microsoftCertFile.getSha256fingerprint()).then().statusCode(204);
    }

}