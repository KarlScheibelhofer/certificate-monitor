package dev.scheibelhofer.certificate.monitor;

import static io.quarkiverse.loggingjson.providers.KeyValueStructuredArgument.kv;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
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
		Log.infof("getById", kv("stats", Map.of("code", "0", "duration", Double.valueOf((t1 - t0)/1e6).toString())));
		return c;
	}

	// public Collection<Key> getAll() {
	// 	Log.infof("getAll", kv("logId", logId));
	// 	return Key.listAll();
	// }

	// public Collection<Key> getByName(String name) {
	// 	return Key.findByName(name);
	// }

	public Certificate create(byte[] encodedCertificate) throws GeneralSecurityException {
		Log.info(logId + " - create");

		Certificate c = createFromEncoding(encodedCertificate);
		c.persist();

		return c;
	}

	public static Certificate createFromEncoding(byte[] encodedCertificate) throws GeneralSecurityException {
		Certificate c = new Certificate();
			
		X509Certificate x509Certificate =  Utils.parseCertificate(encodedCertificate);
		
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] certificateFingerprint = md.digest(x509Certificate.getEncoded());
		
		c.id = HexFormat.of().formatHex(certificateFingerprint);
		c.pemEncoded = Utils.pemEncode(x509Certificate.getEncoded(), "CERTIFICATE");
		c.subjectDN = x509Certificate.getSubjectX500Principal().getName();
		c.issuerDN = x509Certificate.getIssuerX500Principal().getName();
		c.validNotBefore = x509Certificate.getNotBefore().toInstant().atOffset(ZoneOffset.UTC).toLocalDateTime();
		c.validNotAfter = x509Certificate.getNotAfter().toInstant().atOffset(ZoneOffset.UTC).toLocalDateTime();
		
		return c;
    }
	
}
