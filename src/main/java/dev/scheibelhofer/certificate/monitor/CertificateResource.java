package dev.scheibelhofer.certificate.monitor;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Path("/certificates")
public class CertificateResource {

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public String hello() {
        return "Hello RESTEasy";
    }

    @POST
    @Consumes(MediaType.WILDCARD)
    public Response importCertificate(byte[] encodedCertificate) { 
        try {
            Certificate certificate = Certificate.create(encodedCertificate);
            return Response.status(Response.Status.CREATED).entity(certificate).build();
        } catch (Exception e) {
            throw new BadRequestException("invalid certificate", e);
        }
    }
    
}