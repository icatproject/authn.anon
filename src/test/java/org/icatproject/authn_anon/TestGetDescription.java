package org.icatproject.authn_anon;

import static org.junit.Assert.assertEquals;

import org.icatproject.authentication.Authenticator;
import org.junit.Test;

public class TestGetDescription {
	@Test
	public void test() throws Exception {
		Authenticator a = new ANON_Authenticator();
		assertEquals("{\"keys\":[]}", a.getDescription());
	}
}