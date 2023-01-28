package dev.scheibelhofer.certificate.monitor;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public final class Utils {

    public static X509Certificate parseCertificate(byte[] encodedCertificate) throws GeneralSecurityException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate x509Certificate = (X509Certificate) cf
                .generateCertificate(new ByteArrayInputStream(encodedCertificate));
        return x509Certificate;
    }    

    public static String pemEncode(byte[] binary, String pemTypeName) {
        StringBuffer buffer = new StringBuffer();
        buffer.append("-----").append("BEGIN ").append(pemTypeName).append("-----").append("\r\n");
        buffer.append(Base64.getMimeEncoder().encodeToString(binary)).append("\r\n");
        buffer.append("-----").append("END ").append(pemTypeName).append("-----").append("\r\n");
        return buffer.toString();
    }
}
