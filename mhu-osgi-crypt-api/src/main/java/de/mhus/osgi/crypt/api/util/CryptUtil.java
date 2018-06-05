package de.mhus.osgi.crypt.api.util;

import java.util.Date;

import de.mhus.lib.core.crypt.pem.PemBlock;
import de.mhus.lib.core.crypt.pem.PemBlockModel;
import de.mhus.lib.core.crypt.pem.PemPriv;
import de.mhus.lib.core.crypt.pem.PemPub;
import de.mhus.lib.errors.MException;

public class CryptUtil {

	public static void prepareSignOut(PemPriv key, PemBlockModel out, String name) {
		out.set(PemBlock.METHOD,name);
		if (key.isProperty(PemBlock.IDENT))
			out.set(PemBlock.PRIV_ID, key.getProperty(PemBlock.IDENT));
		if (key.isProperty(PemBlock.PUB_ID))
			out.set(PemBlock.PUB_ID, key.getProperty(PemBlock.PUB_ID));
		out.set(PemBlock.CREATED, new Date());
	}

	public static void prepareCipherOut(PemPub key, PemBlockModel out, String name, String stringEncoding) throws MException {
		out.set(PemBlock.METHOD, name);
		if (stringEncoding != null)
			out.set(PemBlock.STRING_ENCODING, stringEncoding);
		if (key.isProperty(PemBlock.IDENT))
			out.set(PemBlock.PUB_ID, key.getString(PemBlock.IDENT));
		if (key.isProperty(PemBlock.PRIV_ID))
			out.set(PemBlock.PRIV_ID, key.getString(PemBlock.PRIV_ID));
		out.set(PemBlock.CREATED, new Date());
	}

	public static void prepareSymmetricCipherOut(PemPub key, PemBlockModel out, String name, String stringEncoding) throws MException {
		out.set(PemBlock.METHOD, name);
		out.set(PemBlock.SYMMETRIC, true);
		if (stringEncoding != null)
			out.set(PemBlock.STRING_ENCODING, stringEncoding);
		if (key.isProperty(PemBlock.IDENT))
			out.set(PemBlock.KEY_ID, key.getString(PemBlock.IDENT));
		out.set(PemBlock.CREATED, new Date());
	}

}
