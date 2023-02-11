package dev.scheibelhofer.certificate.monitor;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public final class Utils {

    private Utils() {}

    public static X509Certificate parseCertificate(byte[] encodedCertificate) throws GeneralSecurityException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(encodedCertificate));
    }    

    public static String pemEncode(byte[] binary, String pemTypeName) {
        StringBuilder buffer = new StringBuilder();
        buffer.append("-----").append("BEGIN ").append(pemTypeName).append("-----").append("\r\n");
        buffer.append(Base64.getMimeEncoder().encodeToString(binary)).append("\r\n");
        buffer.append("-----").append("END ").append(pemTypeName).append("-----").append("\r\n");
        return buffer.toString();
    }
}
