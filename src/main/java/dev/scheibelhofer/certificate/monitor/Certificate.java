package dev.scheibelhofer.certificate.monitor;

import java.time.OffsetDateTime;

import io.quarkus.mongodb.panache.PanacheMongoEntity;

public class Certificate extends PanacheMongoEntity {
    /** The SHA-256 fingerprint of the certificate serves as its ID. */
    public  String id;

    public  String pemEncoded;
    public  String subjectDN;
    public  String issuerDN;
	public  OffsetDateTime validNotBefore;
	public  OffsetDateTime validNotAfter;

}
