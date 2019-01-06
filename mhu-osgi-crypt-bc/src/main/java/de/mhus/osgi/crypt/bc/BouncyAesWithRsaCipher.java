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

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.osgi.service.component.ComponentContext;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import de.mhus.lib.core.IProperties;
import de.mhus.lib.core.MApi;
import de.mhus.lib.core.MLog;
import de.mhus.lib.core.MProperties;
import de.mhus.lib.core.MString;
import de.mhus.lib.core.crypt.Blowfish;
import de.mhus.lib.core.crypt.MBouncy;
import de.mhus.lib.core.crypt.MRandom;
import de.mhus.lib.core.crypt.pem.PemBlock;
import de.mhus.lib.core.crypt.pem.PemBlockModel;
import de.mhus.lib.core.crypt.pem.PemKey;
import de.mhus.lib.core.crypt.pem.PemKeyPair;
import de.mhus.lib.core.crypt.pem.PemPair;
import de.mhus.lib.core.crypt.pem.PemPriv;
import de.mhus.lib.core.crypt.pem.PemPub;
import de.mhus.lib.core.util.Base64;
import de.mhus.lib.errors.MException;
import de.mhus.osgi.crypt.api.CryptApi;
import de.mhus.osgi.crypt.api.cipher.CipherProvider;
import de.mhus.osgi.crypt.api.util.CryptUtil;

// https://bouncycastle-pgp-cookbook.blogspot.de/2013/01/generating-rsa-keys.html

@Component(properties="cipher=AESWITHRSA-BC",immediate=true) // Bouncycastle RSA
public class BouncyAesWithRsaCipher extends MLog implements CipherProvider {

	private final String NAME = "AESwithRSA-BC";
	
	@Activate
	public void doActivate(ComponentContext ctx) {
		MBouncy.init();
	}
	
	@Override
	public PemBlock encrypt(PemPub key, String content) throws MException {
		try {
			// prepare AES key
			int aesLength = key.getInt("AesLength", 128);
			if (aesLength != 128 && aesLength != 256) {
				throw new MException("AES length not valid, use 128 or 256",aesLength);
			}
			int aesSize = aesLength == 128 ? 16 : 32;
			byte[] aesKey = new byte[aesSize];
			MRandom random = MApi.lookup(MRandom.class);
			for (int i = 0; i < aesKey.length; i++)
				aesKey[i] = random.getByte();

			// prepare RSA
			byte[] encKey = key.getBytesBlock();
			X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
			PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

			Cipher cipher = Cipher.getInstance("RSA", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
			
			String stringEncoding = "utf-8";
			
			// encode AES key
			byte[] aesKeyEncoded = cipher.doFinal(aesKey, 0, aesKey.length);
			
			// encode content
			byte[] dataToSend = content.getBytes(stringEncoding);
			Cipher c = Cipher.getInstance("AES", "BC");
			SecretKeySpec k = new SecretKeySpec(aesKey, "AES");
			c.init(Cipher.ENCRYPT_MODE, k);
			byte[] encryptedData = c.doFinal(dataToSend);

			
			PemBlockModel out = new PemBlockModel(PemBlock.BLOCK_CIPHER, encryptedData);
			CryptUtil.prepareCipherOut(key, out, getName(), stringEncoding);
			out.setInt("AesLength", aesLength);
			out.setString("AesKey", Base64.encode(aesKeyEncoded));
			return out;

		} catch (Throwable t) {
			if (t instanceof MException) throw (MException)t;
			throw new MException(t);
		}
	}

	@Override
	public String decrypt(PemPriv key, PemBlock encoded, String passphrase) throws MException {
		try {
			
			
			byte[] encKey = key.getBytesBlock();
			if (MString.isSet(passphrase))
				encKey = Blowfish.decrypt(encKey, passphrase);
			PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(encKey);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
			PrivateKey privKey = keyFactory.generatePrivate(privKeySpec);

			Cipher cipher = Cipher.getInstance("RSA", "BC");
			cipher.init(Cipher.DECRYPT_MODE, privKey);
						
			String aesEncKey = encoded.getString("AesKey");
			byte[] b = Base64.decode(aesEncKey);
			
			byte[] aesKey = cipher.doFinal(b, 0, b.length);
			
			byte[] data = encoded.getBytesBlock();
			Cipher c = Cipher.getInstance("AES");
			SecretKeySpec k = new SecretKeySpec(aesKey, "AES");
			c.init(Cipher.DECRYPT_MODE, k);
			byte[] enc = c.doFinal(data);
			
			String stringEncoding = encoded.getString(PemBlock.STRING_ENCODING, "utf-8");
			return new String(enc, stringEncoding);
		
		} catch (Exception e) {
			if (e instanceof MException) throw (MException)e;
			throw new MException(e);
		}
	}

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public PemPair createKeys(IProperties properties) throws MException {
		try {
			if (properties == null) properties = new MProperties();
			int len = properties.getInt(CryptApi.LENGTH, 1024);
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
			MRandom random = MApi.lookup(MRandom.class);
			keyGen.initialize(len, random.getSecureRandom());
			
			KeyPair    pair = keyGen.generateKeyPair();
			PrivateKey priv = pair.getPrivate();
			PublicKey  pub  = pair.getPublic();
			
			UUID privId = UUID.randomUUID();
			UUID pubId = UUID.randomUUID();

			byte[] privBytes = priv.getEncoded();
			String passphrase = properties.getString(CryptApi.PASSPHRASE, null);
			if (MString.isSet(passphrase))
				privBytes = Blowfish.encrypt(privBytes, passphrase);

			PemKey xpub  = new PemKey(PemBlock.BLOCK_PUB , pub.getEncoded(), false  )
					.set(PemBlock.METHOD, getName())
					.set(PemBlock.LENGTH, len)
					.set(PemBlock.FORMAT, pub.getFormat())
					.set(PemBlock.IDENT, pubId)
					.set(PemBlock.PRIV_ID, privId);
			PemKey xpriv = new PemKey(PemBlock.BLOCK_PRIV, privBytes, true )
					.set(PemBlock.METHOD, getName())
					.set(PemBlock.LENGTH, len)
					.set(PemBlock.FORMAT, priv.getFormat())
					.set(PemBlock.IDENT, privId)
					.set(PemBlock.PUB_ID, pubId);
			
			if (MString.isSet(passphrase))
				xpriv.set(PemBlock.ENCRYPTED, PemBlock.ENC_BLOWFISH);
			privBytes = null;
			return new PemKeyPair(xpriv, xpub);
			
		} catch (Exception e) {
			throw new MException(e);
		}
	}

}
