package de.mhus.osgi.crypt.api;

import de.mhus.lib.core.crypt.pem.PemBlock;

public class NotDecryptedException extends CryptException {

	private static final long serialVersionUID = 1L;

	public NotDecryptedException(PemBlock in) {
		super("",in);
	}

	
}
