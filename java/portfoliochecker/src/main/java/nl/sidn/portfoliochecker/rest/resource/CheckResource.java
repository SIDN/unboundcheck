package nl.sidn.portfoliochecker.rest.resource;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.Response.Status;

import nl.sidn.dnslib.types.ResourceRecordType;
import nl.sidn.portfoliochecker.logic.Checker;

/**
 * REST resource for the /check url
 * a domainname and an optional type can be passed as parameters.
 *
 */
@Path("/")
public class CheckResource {

	/**
	 * lookup without a domain name results in an http 404.
	 * @return http 404 response
	 */
	@GET
	public Response lookup(){
		return Response.status(Status.NOT_FOUND).type(MediaType.TEXT_PLAIN_TYPE).build();
	}

	/**
	 * Lookup a domainname without and explicit type, the type NS will be
	 * used.
	 * @param qName the domain name to query
	 * @return result of the query
	 */
	@GET
	@Path("/{qName}")
	public Response lookupQname(@PathParam("qName") String qName){
		String result = Checker.doLookup(qName, ResourceRecordType.NS.name());
		ResponseBuilder rBuild = Response.ok(result, MediaType.TEXT_PLAIN_TYPE);
        return rBuild.build();
	}
	
	/**
	 * Lookup a domain name and a specific RR type.
	 * @param qName the domain name to query
	 * @param qType the RR type to query for.
	 * @return the response.
	 */
	@Path("/{qName}/{qType}")
	@GET
	public Response lookupQnameAndType(@PathParam("qName") String qName, @PathParam("qType") String qType){
		String result = Checker.doLookup(qName, qType);
		ResponseBuilder rBuild = Response.ok(result, MediaType.TEXT_PLAIN_TYPE);
        return rBuild.build();			
	}

	
}
