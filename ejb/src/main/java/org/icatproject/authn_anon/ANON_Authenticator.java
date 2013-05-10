package org.icatproject.authn_anon;

import java.io.File;
import java.io.FileInputStream;
import java.util.Map;
import java.util.Properties;

import javax.annotation.PostConstruct;
import javax.ejb.Remote;
import javax.ejb.Stateless;

import org.apache.log4j.Logger;
import org.icatproject.authentication.AddressChecker;
import org.icatproject.authentication.Authentication;
import org.icatproject.authentication.Authenticator;
import org.icatproject.core.IcatException;

/* Mapped name is to avoid name clashes */
@Stateless(mappedName = "org.icatproject.authn_anon.ANON_Authenticator")
@Remote
public class ANON_Authenticator implements Authenticator {

	private static final Logger log = Logger.getLogger(ANON_Authenticator.class);
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
			String msg = "Unable to read property file " + f.getAbsolutePath() + "  "
					+ e.getMessage();
			log.fatal(msg);
			throw new IllegalStateException(msg);

		}
		String authips = props.getProperty("ip");
		if (authips != null) {
			try {
				addressChecker = new AddressChecker(authips);
			} catch (IcatException e) {
				String msg = "Problem creating AddressChecker with information from "
						+ f.getAbsolutePath() + "  " + e.getMessage();
				log.fatal(msg);
				throw new IllegalStateException(msg);
			}
		}

		// Note that the mechanism is optional
		mechanism = props.getProperty("mechanism");

		log.debug("Initialised ANON_Authenticator");
	}

	@Override
	public Authentication authenticate(Map<String, String> credentials, String remoteAddr)
			throws IcatException {

		if (addressChecker != null) {
			if (!addressChecker.check(remoteAddr)) {
				throw new IcatException(IcatException.IcatExceptionType.SESSION,
						"authn_db does not allow log in from your IP address " + remoteAddr);
			}
		}

		log.info("Address checker has accepted anon request");
		return new Authentication("anon", mechanism);

	}

}
