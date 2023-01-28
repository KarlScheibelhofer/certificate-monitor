package dev.scheibelhofer.certificate.monitor;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HexFormat;

import io.quarkus.runtime.annotations.RegisterForReflection;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
@RegisterForReflection
public class Certificate {
    /** The SHA-256 fingerprint of the certificate serves as its ID. */
    private String id;

    private String pemEncoded;
    private String subjectDN;
    private String issuerDN;
	private OffsetDateTime validNotBefore;
	private OffsetDateTime validNotAfter;

    public static Certificate create(byte[] encodedCertificate) throws GeneralSecurityException {
        X509Certificate x509Certificate =  Utils.parseCertificate(encodedCertificate);

        String subjectDN = x509Certificate.getSubjectX500Principal().getName();
        String issuerDN = x509Certificate.getIssuerX500Principal().getName();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] certificateFingerprint = md.digest(x509Certificate.getEncoded());
        String certificateId = HexFormat.of().formatHex(certificateFingerprint);
        String pemEncodedCertificate = Utils.pemEncode(x509Certificate.getEncoded(), "CERTIFICATE");
        OffsetDateTime validNotBefore = x509Certificate.getNotBefore().toInstant().atOffset(ZoneOffset.UTC);
        OffsetDateTime validNotAfter = x509Certificate.getNotAfter().toInstant().atOffset(ZoneOffset.UTC);

        return new Certificate(certificateId, pemEncodedCertificate, subjectDN, issuerDN, validNotBefore, validNotAfter);
    }

}
