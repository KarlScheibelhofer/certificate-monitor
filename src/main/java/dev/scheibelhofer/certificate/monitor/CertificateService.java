package dev.scheibelhofer.certificate.monitor;

import static io.quarkiverse.loggingjson.providers.KeyValueStructuredArgument.kv;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import javax.enterprise.context.ApplicationScoped;

import org.eclipse.microprofile.config.inject.ConfigProperty;

import io.quarkus.logging.Log;

@ApplicationScoped
public class CertificateService {

    @ConfigProperty(name = "certificates.log-id", defaultValue = "certificate-monitor")
    String logId;

    public Certificate getById(String id) {
        long t0 = System.nanoTime();
        Certificate c = Certificate.findById(id);
        long t1 = System.nanoTime();
        Log.infof("getById", kv("stats", Map.of(
            "id", id, 
            "duration", Double.toString((t1 - t0)/1e6),
            "found", Boolean.valueOf(c != null))));
        return c;
    }

    public Collection<Certificate> getAll() {
        Log.infof("getAll", kv("logId", logId));
        return Certificate.listAll();
    }

    public Collection<Certificate> getBySubjectName(String name) {
        return Certificate.findBySubjectName(name);
    }

    public Collection<Certificate> getByDNSName(String name) {
        return Certificate.findByDNSName(name);
    }
    
    public String extraxtId(X509Certificate x509Certificate) throws GeneralSecurityException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] certificateFingerprint = md.digest(x509Certificate.getEncoded());
        
        return HexFormat.of().formatHex(certificateFingerprint);
    }

    public Certificate find(X509Certificate x509Certificate) throws GeneralSecurityException {
        Log.info(logId + " - find");

        String id = extraxtId(x509Certificate);

        Certificate c = getById(id);
        if (c != null) {
            Log.infof("found existing certificate", kv("event", Map.of("id", id)));
        }

        return c;
    }

    public Certificate create(X509Certificate x509Certificate) throws GeneralSecurityException {
        Log.info(logId + " - create");
        long t0 = System.nanoTime();
        
        Certificate c = new Certificate();
        setProperties(c, x509Certificate);
        c.persist();
        
        Log.infof("created certificate", kv("event", Map.of("id", c.id)));
        long t1 = System.nanoTime();

        Log.infof("create", kv("stats", Map.of("id", c.id, "duration", Double.toString((t1 - t0)/1e6))));

        return c;
    }

    public void setProperties(Certificate c, X509Certificate x509Certificate) throws GeneralSecurityException {
        c.id = extraxtId(x509Certificate);
        c.pemEncoded = Utils.pemEncode(x509Certificate.getEncoded(), "CERTIFICATE");
        c.subjectDN = x509Certificate.getSubjectX500Principal().getName();
        c.dnsNames = extractDNSNames(x509Certificate);
        c.issuerDN = x509Certificate.getIssuerX500Principal().getName();
        c.serial = x509Certificate.getSerialNumber().toString(16);
        c.validNotBefore = x509Certificate.getNotBefore().toInstant();
        c.validNotAfter = x509Certificate.getNotAfter().toInstant();
    }

    private List<String> extractDNSNames(X509Certificate cert) throws CertificateParsingException {
        // see https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/cert/X509Certificate.html#getSubjectAlternativeNames()
        List<String> dnsNameList = new ArrayList<>();
        Collection<List<?>> subjAltNames = cert.getSubjectAlternativeNames();
        if (subjAltNames == null) {
            return dnsNameList;
        }
        for (List<?> altName: subjAltNames) {
            Integer type = (Integer) altName.get(0);
            if (Integer.valueOf(2).equals(type)) {
                String dnsName = (String) altName.get(1);
                dnsNameList.add(dnsName);
            }
        }
        return dnsNameList;
    }

    public boolean delete(String id) {
        Certificate c = getById(id);
        if (c != null) {
            Log.infof("found certificate to delete", kv("event", Map.of("id", id)));
            c.delete();
            return true;
        } else {
            Log.infof("found no certificate with given id", kv("event", Map.of("id", id)));
            return false;
        }
    }

    public long deleteAll() {
        return Certificate.deleteAll();
    }

    public Collection<Certificate> getByExpiration(String expiring) {
        Duration duration = Duration.parse(expiring);
        Instant expirationTime = Instant.now().plus(duration);
        return Certificate.findExpiringBefore(expirationTime);
    }

}
