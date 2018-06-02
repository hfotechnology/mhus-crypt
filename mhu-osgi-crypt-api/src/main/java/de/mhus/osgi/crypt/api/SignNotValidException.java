package de.mhus.osgi.crypt.api;

import de.mhus.lib.core.crypt.pem.PemBlock;

public class SignNotValidException extends CryptException {

	private static final long serialVersionUID = 1L;

	public SignNotValidException(PemBlock in) {
		super("",in);
	}

	
}
