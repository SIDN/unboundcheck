package nl.sidn.portfoliochecker.logic;

import java.util.ArrayList;
import java.util.List;

import nl.sidn.dnslib.logic.Context;
import nl.sidn.dnslib.logic.LookupResult;
import nl.sidn.dnslib.logic.Resolver;
import nl.sidn.dnslib.logic.ResolverContextBuilder;
import nl.sidn.dnslib.types.ResourceRecordClass;
import nl.sidn.dnslib.types.ResourceRecordType;

import org.apache.commons.lang.StringUtils;

/**
 * Imlements the logic of the portfoliochecker, it calls the resolver
 * and translates the resolver response to an answer for the user. 
 *
 */
public class Checker {
	
	private static String getStatus(LookupResult result){
		if(result.isHaveData()){
			
			if(result.isSecure()){
				return "secure";
			}else if(result.isBogus()){
				return "bogus";
			}

			return "insecure";
		}
		
		return "\"\"";
	}
	
	private static String getMessage(LookupResult result){
		if(result.getWhyBogus() != null){
			return result.getWhyBogus();
		}
		

		return "\"\"";
	}
	
	private static String getError(LookupResult result){
		
		if(!result.isHaveData()){
			return "nodata";
		}
		
		if(result.getStatus() != null && result.getStatus().length() > 0){
			return result.getStatus();
		}
		

		return "\"\"";
	}
	
	/**
	 * Create the result whch is returned to the client.
	 * @param result the resolver response.
	 */
	private static String createResultLine(LookupResult result ){
		return result.getqName() + "," + getError(result) + "," + getStatus(result) + "," + getMessage(result); 
	}
	
	/**
	 * Lookup a single domain name.
	 * @param qName the name tolookup
	 * @param qType the rr type, if the type is null the type NS is used.
	 * @return the result for the client.
	 */
	public static String doLookup(String qName, String qType){
		
		ResourceRecordType type = ResourceRecordType.fromString(qType);
		if(type == null){
			type = ResourceRecordType.NS;
		}

		Context ctx = new ResolverContextBuilder().
				withDnsSecEnabled().
				build();
		
		Resolver r = new Resolver(ctx);
		LookupResult result = r.lookup(StringUtils.trim(qName), type, ResourceRecordClass.IN, true);
		
		return createResultLine(result);
	}
	

	/**
	 * Lookup multiple domain names, the result is a list of response lines
	 * @param domains list of domains to query
	 * @return list of answers.
	 */
	public static List<String> doLookup(List<String> domains){
		
		List<String> results = new ArrayList<>();
		
		for (String domain : domains) {
			
			Context ctx = new ResolverContextBuilder().
					withDnsSecEnabled().
					build();
			
			Resolver r = new Resolver(ctx);
			
			LookupResult result = r.lookup(StringUtils.trim(domain), ResourceRecordType.NS, ResourceRecordClass.IN, false);
			
			if(result.isBogus()){
				//add to top
				results.add(0, createResultLine(result));
			}else{
				results.add(createResultLine(result));
			}
			
		}
		return results;
	}
	

}
