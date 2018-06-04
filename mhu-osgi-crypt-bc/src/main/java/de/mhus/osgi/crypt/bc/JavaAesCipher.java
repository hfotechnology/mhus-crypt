package de.mhus.osgi.crypt.bc;

import java.util.Date;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import aQute.bnd.annotation.component.Component;
import de.mhus.lib.core.IProperties;
import de.mhus.lib.core.MLog;
import de.mhus.lib.core.MPassword;
import de.mhus.lib.core.crypt.pem.PemBlock;
import de.mhus.lib.core.crypt.pem.PemBlockModel;
import de.mhus.lib.core.crypt.pem.PemKey;
import de.mhus.lib.core.crypt.pem.PemKeyPair;
import de.mhus.lib.core.crypt.pem.PemPair;
import de.mhus.lib.core.crypt.pem.PemPriv;
import de.mhus.lib.core.crypt.pem.PemPub;
import de.mhus.lib.errors.MException;
import de.mhus.osgi.crypt.api.cipher.CipherProvider;

@Component(properties="cipher=AES-JCE") // Default Symmetric AES - Java Cryptography Extension
public class JavaAesCipher extends MLog implements CipherProvider {

	private final String NAME = "AES-JCE";

	@Override
	public PemBlock encode(PemPub key, String content) throws MException {
		try {
			byte[] xkey = key.getBytesBlock();
			String stringEncoding = "utf-8";
			byte[] dataToSend = content.getBytes(stringEncoding);
			Cipher c = Cipher.getInstance("AES");
			SecretKeySpec k = new SecretKeySpec(xkey, "AES");
			c.init(Cipher.ENCRYPT_MODE, k);
			byte[] encryptedData = c.doFinal(dataToSend);
	
			PemBlockModel out = new PemBlockModel(PemBlock.BLOCK_CIPHER, encryptedData);
			out.set(PemBlock.METHOD, getName());
			out.set(PemBlock.STRING_ENCODING, stringEncoding);
			if (key.isProperty(PemBlock.IDENT))
				out.set(PemBlock.KEY_IDENT, key.getString(PemBlock.IDENT));
			out.set(PemBlock.CREATED, new Date());
			
			return out;
		} catch (Throwable t) {
			throw new MException(t);
		}
	}

	@Override
	public String decode(PemPriv key, PemBlock encoded, String passphrase) throws MException {
		try {
			byte[] xkey = key.getBytesBlock();
			byte[] data = encoded.getBytesBlock();
			Cipher c = Cipher.getInstance("AES");
			SecretKeySpec k = new SecretKeySpec(xkey, "AES");
			c.init(Cipher.DECRYPT_MODE, k);
			byte[] enc = c.doFinal(data);
			
			String stringEncoding = encoded.getString(PemBlock.STRING_ENCODING, "utf-8");
			return new String(enc, stringEncoding);
			
		} catch (Throwable t) {
			throw new MException(t);
		}
	}

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public PemPair createKeys(IProperties properties) throws MException {
		int length = properties.getInt("length", 256);
		length = length / 8 * 8;
		String passphrase = MPassword.generate(length / 8, length / 8, true, true, true);
		
		UUID privId = UUID.randomUUID();

		PemKey xpriv = new PemKey(PemBlock.BLOCK_PRIV, passphrase.getBytes(), true )
				.set(PemBlock.METHOD, getName())
				.set(PemBlock.LENGTH, length)
				.set(PemBlock.IDENT, privId);

		return new PemKeyPair(xpriv, xpriv);
	}

}
