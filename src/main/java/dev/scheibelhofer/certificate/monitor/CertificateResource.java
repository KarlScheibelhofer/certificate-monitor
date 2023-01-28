package dev.scheibelhofer.certificate.monitor;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import io.quarkus.logging.Log;

@ApplicationScoped
@Path("/certificates")
public class CertificateResource {

    @Inject
    CertificateService certificateService;    

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public String hello() {
        return "Hello RESTEasy";
    }

    @POST
    @Consumes(MediaType.WILDCARD)
    public Response importCertificate(byte[] encodedCertificate) { 
        try {
            Certificate certificate = certificateService.create(encodedCertificate);
            return Response.status(Response.Status.CREATED).entity(certificate).build();
        } catch (Exception e) {
            throw new BadRequestException("invalid certificate", e);
        }
    }
    
    @GET
    @Path("/{id}")
    public Certificate get(@PathParam("id") String id) {
        Log.debug("get certificate with id " + id);

        return certificateService.getById(id);
    }
    
}