package dev.scheibelhofer.certificate.monitor;

import java.time.Instant;

import org.bson.codecs.pojo.annotations.BsonId;

import io.quarkus.mongodb.panache.PanacheMongoEntityBase;

public class Certificate extends PanacheMongoEntityBase {
    /** The SHA-256 fingerprint of the certificate serves as its ID. */
    @BsonId
    public String id;
    public String pemEncoded;
    public String subjectDN;
    public String issuerDN;
	public Instant validNotBefore;
	public Instant validNotAfter;
}
