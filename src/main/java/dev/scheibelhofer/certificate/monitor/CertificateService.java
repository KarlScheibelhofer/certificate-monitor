package dev.scheibelhofer.certificate.monitor;

import static io.quarkiverse.loggingjson.providers.KeyValueStructuredArgument.kv;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HexFormat;
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
		Log.infof("getById", kv("stats", Map.of("id", id, "duration", Double.valueOf((t1 - t0)/1e6).toString())));
		return c;
	}

	public Collection<Certificate> getAll() {
		Log.infof("getAll", kv("logId", logId));
		return Certificate.listAll();
	}

	public Collection<Certificate> getBySubjectName(String name) {
		return Certificate.findBySubjectName(name);
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

		Log.infof("create", kv("stats", Map.of("id", c.id, "duration", Double.valueOf((t1 - t0)/1e6).toString())));

		return c;
	}

	public void setProperties(Certificate c, X509Certificate x509Certificate) throws GeneralSecurityException {
		c.id = extraxtId(x509Certificate);
		c.pemEncoded = Utils.pemEncode(x509Certificate.getEncoded(), "CERTIFICATE");
		c.subjectDN = x509Certificate.getSubjectX500Principal().getName();
		c.issuerDN = x509Certificate.getIssuerX500Principal().getName();
		c.serial = x509Certificate.getSerialNumber().toString(16);
		c.validNotBefore = x509Certificate.getNotBefore().toInstant();
		c.validNotAfter = x509Certificate.getNotAfter().toInstant();
    }
	
}
