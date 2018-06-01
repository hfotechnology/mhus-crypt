package de.mhus.osgi.crypt.api.util;

import java.util.HashMap;

import de.mhus.lib.core.crypt.pem.PemBlock;
import de.mhus.lib.core.crypt.pem.PemKey;
import de.mhus.lib.core.crypt.pem.PemPriv;
import de.mhus.lib.core.crypt.pem.PemPub;
import de.mhus.lib.core.util.SecureString;
import de.mhus.lib.errors.MException;
import de.mhus.osgi.crypt.api.CryptaException;
import de.mhus.osgi.crypt.api.VaultProcessContext;

public class SimpleVaultProcessContext implements VaultProcessContext {

	protected SecureString lastSecret;
	protected HashMap<String, PemBlock> keys = new HashMap<>();
	protected HashMap<String, SecureString> passphrases = new HashMap<>();
	protected PemBlock lastHash;
	private PemBlock lastValidated;

	@Override
	public void errorKeyNotFound(PemBlock block) throws CryptaException {
		throw new CryptaException("key not found", block);
	}

	@Override
	public PemPriv getPrivateKey(String privId) throws MException {
		PemBlock key = keys.get(privId);
		if (key == null) return null;
		return new PemKey( key );
	}

	@Override
	public String getPrivateIdForPublicKeyId(String pubId) throws CryptaException {
		PemBlock pub = keys.get(pubId);
		if (pub == null) return null;
		return pub.getString(PemBlock.PRIV_ID, null);
	}

	@Override
	public SecureString getPassphrase(String privId, PemBlock block) throws CryptaException {
		return passphrases.get(privId);
	}

	@Override
	public void foundSecret(PemBlock block, SecureString sec) {
		lastSecret = sec;
	}

	public SecureString getLastSecret() {
		return lastSecret;
	}

	@Override
	public void foundPublicKey(PemBlock block) {
		String id = block.getString(PemBlock.KEY_IDENT, null);
		if (id == null) return;
		keys.put(id, block);
	}

	@Override
	public void foundPrivateKey(PemBlock block) {
		String id = block.getString(PemBlock.KEY_IDENT, null);
		if (id == null) return;
		keys.put(id, block);
	}

	@Override
	public PemPub getPublicKey(String pubId) {
		PemBlock key = keys.get(pubId);
		if (key == null) return null;
		return new PemKey( key );
	}

	public void addPassphrase(String privId, SecureString passphrase) {
		passphrases.put(privId, passphrase);
	}

	@Override
	public void foundHash(PemBlock block) {
		lastHash = block;
	}
	
	public PemBlock getLastHash() {
		return lastHash;
	}

	@Override
	public void foundValidated(PemBlock block) {
		lastValidated = block;
	}
	
	public PemBlock getLastValidated() {
		return lastValidated;
	}
	
	
}
