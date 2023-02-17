package dev.scheibelhofer.certificate.monitor;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HexFormat;

import lombok.Data;

@Data
public class CertFile {

    String filename;
    byte[] pemEncodedCertificate;
    X509Certificate certificate; 
    String sha256fingerprint;

    public static CertFile parse(String filename) throws IOException, GeneralSecurityException {
        CertFile certFile = new CertFile();
        certFile.filename = filename;
        certFile.pemEncodedCertificate = CertFile.class.getClassLoader().getResourceAsStream("certificates/" + filename).readAllBytes();
        certFile.certificate = parseX509Certificate(certFile.pemEncodedCertificate);
        certFile.sha256fingerprint = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(certFile.certificate.getEncoded()));
        return certFile;
    }    
    
    private static X509Certificate parseX509Certificate(byte[] encodedCertificate) throws GeneralSecurityException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate x509Certificate = (X509Certificate) cf
                .generateCertificate(new ByteArrayInputStream(encodedCertificate));
        return x509Certificate;
    }    

}
