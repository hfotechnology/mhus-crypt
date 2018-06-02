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
package de.mhus.karaf.crypt;

import aQute.bnd.annotation.component.Component;
import de.mhus.lib.core.MApi;
import de.mhus.lib.core.MLog;
import de.mhus.lib.core.crypt.pem.PemBlock;
import de.mhus.lib.core.crypt.pem.PemBlockList;
import de.mhus.lib.core.crypt.pem.PemPriv;
import de.mhus.lib.core.crypt.pem.PemPub;
import de.mhus.lib.core.crypt.pem.PemUtil;
import de.mhus.lib.core.util.SecureString;
import de.mhus.lib.errors.MException;
import de.mhus.lib.errors.NotFoundException;
import de.mhus.osgi.crypt.api.CryptApi;
import de.mhus.osgi.crypt.api.CryptException;
import de.mhus.osgi.crypt.api.NotDecryptedException;
import de.mhus.osgi.crypt.api.SignNotValidException;
import de.mhus.osgi.crypt.api.VaultProcessContext;
import de.mhus.osgi.crypt.api.cipher.CipherProvider;
import de.mhus.osgi.crypt.api.currency.CurrencyProvider;
import de.mhus.osgi.crypt.api.signer.SignerProvider;
import de.mhus.osgi.services.MOsgi;

@Component
public class CryptApiImpl extends MLog implements CryptApi {

	
	private static final String DEFAULT_SIGN = "BCFIPS-1";
	private static final String DEFAUL_CIPHER = "BCFIPS-1";
	private CipherProvider cipher;
	private SignerProvider signer;

	@Override
	public CipherProvider getCipher(String cipher) throws NotFoundException {
		cipher = normalizeName(cipher);
		return MOsgi.getService(CipherProvider.class, "(cipher="+cipher+")");
	}

	@Override
	public CipherProvider getDefaultCipher() throws NotFoundException {
		if (cipher == null)
			cipher = getCipher(DEFAUL_CIPHER);
		return cipher;
	}

	@Override
	public PemBlock sign(PemPriv key, String text, String passphrase) throws MException {
		SignerProvider sign = getSigner(key.getMethod());
		return sign.sign(key, text, passphrase);
	}
	
	@Override
	public boolean validate(PemPub key, String text, PemBlock sign) throws MException {
		SignerProvider s = getSigner(key.getMethod());
		return s.validate(key, text, sign);
	}
	
	@Override
	public SignerProvider getDefaultSigner() throws NotFoundException {
		if (signer == null)
			signer = getSigner(DEFAULT_SIGN);
		return signer;
	}

	@Override
	public SignerProvider getSigner(String signer) throws NotFoundException {
		signer = normalizeName(signer);
		return MOsgi.getService(SignerProvider.class, "(signer="+signer+")");
	}

	@Override
	public CurrencyProvider getCurrency(String currency) throws NotFoundException {
		currency = normalizeName(currency);
		return MOsgi.getService(CurrencyProvider.class, "(currency="+currency+")");
	}

	private String normalizeName(String currency) {
		return currency.trim().toUpperCase();
	}

	@Override
	public void processPemBlocks(VaultProcessContext context, PemBlockList list) throws MException {
		// iterate all blocks
		int index = 0;
		while (index < list.size()) {
			PemBlock block = list.get(index);
			log().t("process",block);
			Object res = processPemBlock(context, block);
			if (PemUtil.isCipher(block) && block.getBoolean(PemBlock.EMBEDDED, false)) {
				if (res == null)
					throw new NotDecryptedException(block);
				PemBlockList insert = new PemBlockList(((SecureString)res).value());
				log().t("insert",insert);
				list.addAll(index, insert);
			} else
			if (PemUtil.isSign(block) && block.getBoolean(PemBlock.EMBEDDED, false)) {
				if (res == null)
					throw new CryptException("sign key not found",block);
				PemPub key = (PemPub) res;
				// validate against the rest of the block list
				String text = list.toString(index+1,Integer.MAX_VALUE);
				
				SignerProvider api = MApi.lookup(SignerProvider.class);
				boolean valid = api.validate(key, text, block);
				if (!valid)
					throw new SignNotValidException(block);
				context.foundValidated(block);
			}
			index++;
		}
	}

	@Override
	public Object processPemBlock(VaultProcessContext context, PemBlock block) throws MException {
		if (PemUtil.isCipher(block)) {
			// process encrypted content
			PemPriv keyKey = null;
			String keyId = null;
			boolean isSymetric = block.getBoolean(PemBlock.SYMMETRIC, block.isProperty(PemBlock.KEY_ID) );
			if (isSymetric) {
				keyId = block.getString(PemBlock.KEY_ID, null);
				if (keyId == null) {
					log().d("key id not found", block);
					context.errorKeyNotFound(block);
					return null;
				}
			} else {
				keyId = block.getString(PemBlock.PRIV_ID, null);
				if (keyId == null) {
					String pubId = block.getString(PemBlock.PUB_ID, null);
					if (pubId == null) {
						log().d("public key not found", block);
						context.errorKeyNotFound(block);
						return null;
					}
					keyId =  context.getPrivateIdForPublicKeyId(pubId);
					if (keyId == null) {
						log().d("private key not found for public key", block);
						context.errorKeyNotFound(block);
						return null;
					}
				}
			}
			
			keyKey = context.getPrivateKey(keyId);
			if (keyKey == null) {
				log().d("private key not found", block);
				context.errorKeyNotFound(block);
				return null;
			}
		
			CipherProvider api = MApi.lookup(CipherProvider.class);
			String decoded = api.decode(keyKey, block, context.getPassphrase(keyId,block));
			SecureString sec = new SecureString(decoded);
			decoded = "";
			context.foundSecret(block, sec);
			return sec;
		} else
		if (PemUtil.isSign(block)) {
			// no content to validate - not possible in this moment, but will check the key
			String keyId = block.getString(PemBlock.PUB_ID, null);
			if (keyId == null) {
				String privId = block.getString(PemBlock.PRIV_ID, null);
				if (privId == null) {
					log().d("private key not found", block);
					context.errorKeyNotFound(block);
					return null;
				}
				keyId =  context.getPrivateIdForPublicKeyId(privId);
				if (keyId == null) {
					log().d("public key not found for private key", block);
					context.errorKeyNotFound(block);
					return null;
				}
			}
			PemPub keyKey = context.getPublicKey(keyId);
			if (keyKey == null) {
				log().d("public key not found", block);
				context.errorKeyNotFound(block);
				return null;
			}
			return keyKey;
		}
		if (PemUtil.isPubKey(block)) {
			context.foundPublicKey(block);
			return block;
		} else
		if (PemUtil.isPrivKey(block)) {
			context.foundPrivateKey(block);
			return block;
		} else
		if (PemUtil.isHash(block)) {
			context.foundHash(block);
		} else
			log().w("unknown block type",block.getName());
		return null;
	}

}
