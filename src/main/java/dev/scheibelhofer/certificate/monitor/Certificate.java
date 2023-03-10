package dev.scheibelhofer.certificate.monitor;

import static java.lang.String.format;

import java.time.Instant;
import java.util.Collection;
import java.util.List;

import org.bson.codecs.pojo.annotations.BsonId;

import io.quarkus.mongodb.panache.PanacheMongoEntityBase;
import io.quarkus.panache.common.Sort;

public class Certificate extends PanacheMongoEntityBase {
    /** The SHA-256 fingerprint of the certificate serves as its ID. */
    @BsonId
    public String id;
    public String name;
    public String subjectDN;
    public List<String> dnsNames;
    public String issuerDN;
    public String serial;
    public Instant validNotBefore;
    public Instant validNotAfter;
    public String pemEncoded;

    public static List<Certificate> findBySubjectName(String name) {
        return Certificate.list(format("{subjectDN: {$regex: /%s/i}}", name));
    }

    public static List<Certificate> findByDNSName(String name) {
        return Certificate.list(format("{dnsNames: {$regex: /%s/i}}", name));
    }

    public static Collection<Certificate> findExpiringBefore(Instant expirationTime) {
        return Certificate.list("validNotAfter < ?1", Sort.ascending("validNotAfter"), expirationTime);
    }

}
