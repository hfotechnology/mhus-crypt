package de.mhus.karaf.crypt.test;

import de.mhus.karaf.crypt.CryptApiImpl;
import de.mhus.lib.core.MApi;
import de.mhus.lib.core.crypt.pem.PemBlock;
import de.mhus.lib.core.crypt.pem.PemBlockList;
import de.mhus.lib.core.crypt.pem.PemBlockModel;
import de.mhus.lib.core.crypt.pem.PemKey;
import de.mhus.lib.core.logging.Log.LEVEL;
import de.mhus.lib.errors.MException;
import de.mhus.lib.errors.NotFoundException;
import de.mhus.osgi.crypt.api.signer.SignerProvider;
import de.mhus.osgi.crypt.api.util.SimplePemProcessContext;
import de.mhus.osgi.crypt.bc.BouncyUtil;
import de.mhus.osgi.crypt.bc.EccSigner;
import junit.framework.TestCase;

public class PemProcessorTest extends TestCase {
	
	final String content = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet.";

	final String pubKeySign =
	"-----START PUBLIC KEY-----\n"+
	"PrivateKey: cb0b626c-d0a7-4715-8c08-77a75ee9dc14\n"+
	"Ident: 881b7fe7-3bc3-4cd0-ab21-ea52e9d04174\n"+
	"Format: X.509\n"+
	"StdName: prime192v1\n"+
	"Method: ECC-BC\n"+
	"\n"+
	"MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEqqyclMzGZTjvKS\n"+
	"+URxjdm0ueWyuR+3msXeGROatE5+hK0lMzoTLuHazRW2ar2Mz5\n"+
	"\n"+
	"-----END PUBLIC KEY-----\n";

	final String privKeySign =
	"-----START PRIVATE KEY-----\n"+
	"Ident: cb0b626c-d0a7-4715-8c08-77a75ee9dc14\n"+
	"StdName: prime192v1\n"+
	"Format: PKCS#8\n"+
	"PublicKey: 881b7fe7-3bc3-4cd0-ab21-ea52e9d04174\n"+
	"Method: ECC-BC\n"+
	"\n"+
	"MHsCAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQEEYTBfAgEBBBjDOv\n"+
	"ScMgourQ6rU8pDIG033kCUuHby9MygCgYIKoZIzj0DAQGhNAMy\n"+
	"AASqrJyUzMZlOO8pL5RHGN2bS55bK5H7eaxd4ZE5q0Tn6ErSUz\n"+
	"OhMu4drNFbZqvYzPk=\n"+
	"\n"+
	"-----END PRIVATE KEY-----\n";

	final String signature =
	"-----START SIGNATURE-----\n"+
	"PrivateKey: cb0b626c-d0a7-4715-8c08-77a75ee9dc14\n"+
	"PublicKey: 881b7fe7-3bc3-4cd0-ab21-ea52e9d04174\n"+
	"Method: ECC-BC\n"+
	"Created: Mon Jun 04 23:03:44 CEST 2018\n"+
	"Embedded: next\n"+
	"\n"+
	"MDQCGCUa+letqu2rXTo2lhEJ04APuSFpuP2ezQIYJtC52hxcoZ\n"+
	"ms+33vNW8ZCP6kmGw1pfri\n"+
	"\n"+
	"-----END SIGNATURE-----\n";
	
	final String contentBlock = new PemBlockModel(PemBlock.BLOCK_CONTENT,content.getBytes()).toString();
	
	public void testSign() throws MException {
		
		System.out.println(pubKeySign);
		System.out.println(privKeySign);
		
		MApi.get().getLogFactory().setDefaultLevel(LEVEL.TRACE);
		BouncyUtil.init();

		EccSigner signer = new EccSigner();
		boolean valid = signer.validate(new PemKey(new PemBlockModel().parse(pubKeySign)), content, new PemBlockModel().parse(signature));
		if (!valid) throw new MException("not valid");
		
		SimplePemProcessContext context = new SimplePemProcessContext();

		PemBlockList list = new PemBlockList(pubKeySign + signature + contentBlock);
		System.out.println(list);
		
		CryptApiImpl api = new CryptApiImpl() {
			@Override
			public SignerProvider getSigner(String signer) throws NotFoundException {
				if (signer.equals("ECC-BC"))
					return new EccSigner();
				throw new NotFoundException(signer);
			}

		};
		api.processPemBlocks(context, list);
	}
	
}
