package de.mhus.osgi.crypt.api;

import de.mhus.lib.core.crypt.pem.PemBlock;
import de.mhus.lib.core.crypt.pem.PemPriv;
import de.mhus.lib.core.crypt.pem.PemPub;
import de.mhus.lib.core.util.SecureString;
import de.mhus.lib.errors.MException;

public interface VaultProcessContext {

	void errorKeyNotFound(PemBlock block) throws CryptaException;

	PemPriv getPrivateKey(String privId) throws MException;

	String getPrivateIdForPublicKeyId(String pubId) throws CryptaException;

	SecureString getPassphrase(String privId, PemBlock block) throws CryptaException;

	void foundSecret(PemBlock block, SecureString sec);

	void foundPublicKey(PemBlock block);

	void foundPrivateKey(PemBlock block);

	PemPub getPublicKey(String keyId);

	void foundHash(PemBlock block);

	void foundValidated(PemBlock block);
	
}
