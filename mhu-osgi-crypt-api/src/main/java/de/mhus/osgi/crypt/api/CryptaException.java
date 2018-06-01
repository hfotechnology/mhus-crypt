package de.mhus.osgi.crypt.api;

import de.mhus.lib.core.crypt.pem.PemBlock;
import de.mhus.lib.errors.MException;

public class CryptaException extends MException {

	private static final long serialVersionUID = 1L;

	public CryptaException(String msg, PemBlock in) {
		super(msg,in);
	}

	
}
