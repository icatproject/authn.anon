package org.icatproject.authn_anon;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.util.Map;
import java.util.Properties;

import javax.annotation.PostConstruct;
import javax.ejb.Remote;
import javax.ejb.Stateless;
import javax.json.Json;
import javax.json.stream.JsonGenerator;

import org.icatproject.authentication.AddressChecker;
import org.icatproject.authentication.Authentication;
import org.icatproject.authentication.Authenticator;
import org.icatproject.core.IcatException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

/* Mapped name is to avoid name clashes */
@Stateless(mappedName = "org.icatproject.authn_anon.ANON_Authenticator")
@Remote
public class ANON_Authenticator implements Authenticator {

	private static final Logger log = LoggerFactory.getLogger(ANON_Authenticator.class);
	private Marker fatal = MarkerFactory.getMarker("FATAL");
	private org.icatproject.authentication.AddressChecker addressChecker;
	private String mechanism;

	@PostConstruct
	private void init() {
		File f = new File("authn_anon.properties");
		Properties props = null;
		try {
			props = new Properties();
			props.load(new FileInputStream(f));
		} catch (Exception e) {
			String msg = "Unable to read property file " + f.getAbsolutePath() + "  " + e.getMessage();
			log.error(fatal, msg);
			throw new IllegalStateException(msg);

		}
		String authips = props.getProperty("ip");
		if (authips != null) {
			try {
				addressChecker = new AddressChecker(authips);
			} catch (IcatException e) {
				String msg = "Problem creating AddressChecker with information from " + f.getAbsolutePath() + "  "
						+ e.getMessage();
				log.error(fatal, msg);
				throw new IllegalStateException(msg);
			}
		}

		// Note that the mechanism is optional
		mechanism = props.getProperty("mechanism");

		log.info("Initialised ANON_Authenticator");
	}

	@Override
	public Authentication authenticate(Map<String, String> credentials, String remoteAddr) throws IcatException {

		if (addressChecker != null) {
			if (!addressChecker.check(remoteAddr)) {
				throw new IcatException(IcatException.IcatExceptionType.SESSION,
						"authn_db does not allow log in from your IP address " + remoteAddr);
			}
		}

		log.debug("Address checker has accepted anon request");
		return new Authentication("anon", mechanism);

	}

	@Override
	public String getDescription() {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		JsonGenerator gen = Json.createGenerator(baos);
		gen.writeStartObject().writeStartArray("keys");
		gen.writeEnd().writeEnd().close();
		return baos.toString();
	}

}
