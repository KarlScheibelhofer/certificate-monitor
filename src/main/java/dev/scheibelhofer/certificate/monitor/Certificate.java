package dev.scheibelhofer.certificate.monitor;

import static java.lang.String.format;

import java.time.Instant;
import java.util.List;

import org.bson.codecs.pojo.annotations.BsonId;

import io.quarkus.mongodb.panache.PanacheMongoEntityBase;

public class Certificate extends PanacheMongoEntityBase {
    /** The SHA-256 fingerprint of the certificate serves as its ID. */
    @BsonId
    public String id;
    public String pemEncoded;
    public String subjectDN;
    public String issuerDN;
    public String serial;
	public Instant validNotBefore;
	public Instant validNotAfter;

	public static List<Certificate> findBySubjectName(String name) {
		// return find("name", name).list();
        return Certificate.list(format("{subjectDN: {$regex: /.*%s.*/i}}", name));
	}

}
