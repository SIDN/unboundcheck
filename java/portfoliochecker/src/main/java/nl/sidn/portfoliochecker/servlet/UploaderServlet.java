package nl.sidn.portfoliochecker.servlet;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import javax.servlet.ServletException;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;

import nl.sidn.portfoliochecker.logic.Checker;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;

/**
 * Servlet which is used to upload a file containing up to
 * MAX_DOMAINS of domain names to query.
 *
 */
@MultipartConfig(  fileSizeThreshold=1024*1024, maxFileSize=1024*1024, maxRequestSize=1024*1024)
public class UploaderServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;

	private static final long MAX_DOMAINS = 10000;

	private final static Logger LOGGER = Logger.getLogger(UploaderServlet.class
			.getCanonicalName());

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	protected void doGet(HttpServletRequest request,HttpServletResponse response) throws ServletException, IOException {
		// do nothing
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	protected void doPost(HttpServletRequest request,HttpServletResponse response) throws ServletException, IOException {
		processRequest(request, response);
	}

	/**
	 * Proces the http put request and get the uploaded data. The
	 * data must be a list of comma seperated domain names.
	 * 
	 * @param request
	 * @param response
	 * @throws ServletException
	 * @throws IOException
	 */
	private void processRequest(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		response.setContentType("text/plain;charset=UTF-8");

		final Part filePart = request.getPart("domainlist");
		final PrintWriter writer = response.getWriter();
		List<String> toCheck = new ArrayList<>();
		int counter = 0;
		try (InputStream filecontent = filePart.getInputStream();
				Scanner scanner = new Scanner(filecontent).useDelimiter("\\n");){
			
			while (scanner.hasNext()) {
				String line = scanner.next();
				String[] domains = StringUtils.split(line, ",");
				for (int i = 0; i < domains.length; i++) {
					counter++;
					if (counter > MAX_DOMAINS) {
						// bad boy, too many domain names in the posted file. do nothing
						writer.println("Domain limit exceeded, max file size is "
								+ MAX_DOMAINS + " domains");
						return;
					}
				
					toCheck.add(domains[i]);
				}
			}
			
			List<String> results = Checker.doLookup(toCheck);
			for (String result : results) {
				writer.println(result);
			}

		}
	}

}
