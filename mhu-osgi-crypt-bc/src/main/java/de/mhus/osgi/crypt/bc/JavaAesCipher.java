/**
 * Copyright 2018 Mike Hummel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.mhus.osgi.crypt.bc;

import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import aQute.bnd.annotation.component.Component;
import de.mhus.lib.core.IProperties;
import de.mhus.lib.core.MApi;
import de.mhus.lib.core.MLog;
import de.mhus.lib.core.crypt.MRandom;
import de.mhus.lib.core.crypt.pem.PemBlock;
import de.mhus.lib.core.crypt.pem.PemBlockModel;
import de.mhus.lib.core.crypt.pem.PemKey;
import de.mhus.lib.core.crypt.pem.PemKeyPair;
import de.mhus.lib.core.crypt.pem.PemPair;
import de.mhus.lib.core.crypt.pem.PemPriv;
import de.mhus.lib.core.crypt.pem.PemPub;
import de.mhus.lib.errors.MException;
import de.mhus.osgi.crypt.api.cipher.CipherProvider;
import de.mhus.osgi.crypt.api.util.CryptUtil;

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
			CryptUtil.prepareSymmetricCipherOut(key, out, getName(), stringEncoding);
			
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
		byte[] key = new byte[length/8];
		MRandom random = MApi.lookup(MRandom.class);
		for (int i = 0; i < key.length; i++)
			key[i] = random.getByte();
		
		UUID privId = UUID.randomUUID();

		PemKey xpriv = new PemKey(PemBlock.BLOCK_PRIV, key, true )
				.set(PemBlock.METHOD, getName())
				.set(PemBlock.LENGTH, length)
				.set(PemBlock.IDENT, privId);

		return new PemKeyPair(xpriv, xpriv);
	}

}
