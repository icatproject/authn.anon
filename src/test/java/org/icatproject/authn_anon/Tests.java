package org.icatproject.authn_anon;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class Tests {

	@Test
	public void getDescription() {
		ANON_Authenticator authn = new ANON_Authenticator();
		assertEquals("{\"keys\":[]}", authn.getDescription());
	}

}