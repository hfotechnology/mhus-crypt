package de.mhus.osgi.crypt.api;

import de.mhus.lib.core.crypt.pem.PemBlock;
import de.mhus.lib.errors.MException;

public class CryptException extends MException {

	private static final long serialVersionUID = 1L;

	public CryptException(String msg, PemBlock in) {
		super(msg,in);
	}

	
}
