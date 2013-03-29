package nl.sidn.portfoliochecker.rest.resource;

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

import com.sun.jersey.api.NotFoundException;

@Provider
public class NotfoundExceptionMapper implements	ExceptionMapper<NotFoundException> {

	public Response toResponse(NotFoundException exception) {
		return Response.status(Response.Status.NOT_FOUND).build();
	}
}