package dev.scheibelhofer.certificate.monitor;

import java.security.cert.X509Certificate;
import java.util.Collection;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import io.quarkus.logging.Log;

@ApplicationScoped
@Path("/certificates")
public class CertificateResource {

    @Inject
    CertificateService certificateService;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Collection<Certificate> list(@QueryParam("subject") String subject, @QueryParam("dns") String dns, @QueryParam("expiring") String expiring, @QueryParam("sortBy") String sortBy) {
        Log.info("list all certificates as JSON");
        return listCertificates(subject, dns, expiring, sortBy);
    }

    @GET
    @Produces("text/csv; qs=0.9")
    public Response listCSV(@QueryParam("subject") String subject, @QueryParam("dns") String dns, @QueryParam("expiring") String expiring, @QueryParam("sortBy") String sortBy) {
        Log.info("list all certificates as CSV");
        Collection<Certificate> certList = listCertificates(subject, dns, expiring, sortBy);
        String csv = CSVSupport.toCSV(certList);
        return Response.ok(csv).build();
    }

    private Collection<Certificate> listCertificates(String subject, String dns, String expiring, String sortBy) {
        if (subject != null) {
            Log.info("list certificates with subject " + subject);
            return certificateService.getBySubjectName(subject);
        }
        if (dns != null) {
            Log.info("list certificates with DNS " + dns);
            return certificateService.getByDNSName(dns);
        }
        if (expiring != null) {
            Log.info("list certificates expiring in " + expiring);
            return certificateService.getByExpiration(expiring);
        }

        Log.info("list all certificates");
        return certificateService.getAll(sortBy);
    }

    @GET
    @Path("/{id}")
    public Certificate get(@PathParam("id") String id) {
        Log.debug("get certificate with id " + id);

        return certificateService.getById(id);
    }

    @DELETE
    public Response delete() {
        Log.info("delete all certificates");
        long entriesDeleted = certificateService.deleteAll();
        Log.info("deletes number of certificates " + entriesDeleted);
        return Response.noContent().build();
    }

    @DELETE
    @Path("/{id}")
    public Response delete(@PathParam("id") String id) {
        Log.info("delete certificate with id " + id);
        if (certificateService.delete(id) == false) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        return Response.noContent().build();
    }

    @POST
    @Consumes(MediaType.WILDCARD)
    public Response postCertificate(byte[] encodedCertificate) {
        Log.debug("post certificate");
        try {
            X509Certificate x509Certificate = Utils.parseCertificate(encodedCertificate);
            Certificate certificate = certificateService.find(x509Certificate);
            if (certificate != null) {
                return Response.status(Response.Status.OK).entity(certificate).build();
            }
            certificate = certificateService.create(x509Certificate);
            return Response.status(Response.Status.CREATED).entity(certificate).build();
        } catch (Exception e) {
            throw new BadRequestException("invalid certificate", e);
        }
    }

}