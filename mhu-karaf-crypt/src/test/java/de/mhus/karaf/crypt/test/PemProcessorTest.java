package de.mhus.karaf.crypt.test;

import de.mhus.karaf.crypt.CryptApiImpl;
import de.mhus.lib.core.MApi;
import de.mhus.lib.core.crypt.BouncyUtil;
import de.mhus.lib.core.crypt.pem.PemBlock;
import de.mhus.lib.core.crypt.pem.PemBlockList;
import de.mhus.lib.core.crypt.pem.PemBlockModel;
import de.mhus.lib.core.crypt.pem.PemUtil;
import de.mhus.lib.core.logging.Log.LEVEL;
import de.mhus.lib.core.parser.ParseException;
import de.mhus.lib.errors.MException;
import de.mhus.lib.errors.NotFoundException;
import de.mhus.osgi.crypt.api.cipher.CipherProvider;
import de.mhus.osgi.crypt.api.signer.SignerProvider;
import de.mhus.osgi.crypt.api.util.SimplePemProcessContext;
import de.mhus.osgi.crypt.bc.EccSigner;
import de.mhus.osgi.crypt.bc.JavaRsaCipher;
import junit.framework.TestCase;

public class PemProcessorTest extends TestCase {
	
	final String content = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua.";

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
	"Embedded: next\n"+
	"Created: Tue Jun 05 22:06:04 CEST 2018\n"+
	"\n"+
	"MDUCGQDhooTUN9PFaHvmoRJROcp17JCf96W9i9wCGG6ZyOz2HL\n"+
	"WA4YPR3+dOtPup095HbN5Brw==\n"+
	"\n"+
	"-----END SIGNATURE-----\n";
		
	final String contentBlock = new PemBlockModel(PemBlock.BLOCK_CONTENT,content.getBytes()).toString();
	
	final String privKeyCipher =
	"-----START PRIVATE KEY-----\n"+
	"Ident: 5fe815c6-954d-4dbf-b581-4dc6e05dc17c\n"+
	"Format: PKCS#8\n"+
	"Length: 1024\n"+
	"PublicKey: 12657d2c-b73a-4be0-a5a2-037d835697cb\n"+
	"Method: RSA-JCE\n"+
	"Created: Tue Jun 05 21:52:45 CEST 2018\n"+
	"\n"+
	"MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAI\n"+
	"gdxYtSYUlaVCv9zYPpiybNYLv2OSXZdBHqIDaTokJ5QCtb0rj4\n"+
	"JH8+ngBLiBv1gx1wuwkPNdjDPFfUeP/mRLe/1jjravf4FMISX/\n"+
	"bOlhd3OqsZYlGrZJieUvaIJ6zdqXKBwwADopBIp3ThMe+yTpSB\n"+
	"KVIxswM5CEvjeyI+AYqXAgMBAAECgYA/1a6CM0U60GjvJJ0QQy\n"+
	"OmM+Us4UFV1dBQYntu/Pe4swJ8ExkU9BKxth0FSGbxrccqtGaS\n"+
	"zhZTrOQM0LFaWZRZ3ZimZUZ6G1UdScArApBNz2uGiou84tfnEL\n"+
	"HJmqmG68nz8GWhfrIXx2ezPCauKMbbO6KfMmqxtGqGqeUfMRc/\n"+
	"mQJBAPqgPXwxt/HUL+CAeA8AWv9myOyM03FXzd1Bhcl3wZkoGU\n"+
	"Tg6qQ6dKnssCMlipPFK2+viRazqYiEg4LbsbRLSksCQQCLCPRH\n"+
	"vnT1YBNVN/h3V7Jb0ETX0JeElP4w1NnQmBFFexh3buHev3g4ff\n"+
	"4shSqxqi+eAiD0M12YUx05YqsmMtFlAkAiRMDDd4TgQxQczVQd\n"+
	"MP5AR8yXU5YhvFDAvRHO/1nwWCREX8CVngyPo3ZeB+cP13jd95\n"+
	"F2EjDPItdckC+XKGhLAkAEXjymgGJWTzVsSPziavvsjIeNLD2G\n"+
	"adPuntFVD2IDh9GF9xLbl7JkO/kfVvO3bzxdv31fjrmTDpFtex\n"+
	"8bbR9NAkBAQWpAQ1wsYznQFBIkMlLTt/rM8C3rBwMr+eLjmX3p\n"+
	"JFdw7BXHVtGQrTeBHgchoMSXkYJXlDQTTmdJ0vBMpx6s\n"+
	"\n"+
	"-----END PRIVATE KEY-----\n";

	final String pubKeyCipher =
	"-----START PUBLIC KEY-----\n"+
	"Ident: 12657d2c-b73a-4be0-a5a2-037d835697cb\n"+
	"Format: X.509\n"+
	"PrivateKey: 5fe815c6-954d-4dbf-b581-4dc6e05dc17c\n"+
	"Length: 1024\n"+
	"Method: RSA-JCE\n"+
	"Created: Tue Jun 05 21:52:45 CEST 2018\n"+
	"\n"+
	"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCIHcWLUmFJWl\n"+
	"Qr/c2D6YsmzWC79jkl2XQR6iA2k6JCeUArW9K4+CR/Pp4AS4gb\n"+
	"9YMdcLsJDzXYwzxX1Hj/5kS3v9Y462r3+BTCEl/2zpYXdzqrGW\n"+
	"JRq2SYnlL2iCes3alygcMAA6KQSKd04THvsk6UgSlSMbMDOQhL\n"+
	"43siPgGKlwIDAQAB\n"+
	"\n"+
	"-----END PUBLIC KEY-----\n";
		
	final String cipherBlock =
	"-----START CIPHER-----\n"+
	"PrivateKey: 5fe815c6-954d-4dbf-b581-4dc6e05dc17c\n"+
	"PublicKey: 12657d2c-b73a-4be0-a5a2-037d835697cb\n"+
	"Encoding: utf-8\n"+
	"Method: RSA-JCE\n"+
	"Embedded: true\n"+
	"Created: Tue Jun 05 22:27:22 CEST 2018\n"+
	"\n"+
	"cL4o53iB3Va6J5ZF/tNxRNZnnueDEV1mVdQsVeYdG5L89FjpW0\n"+
	"UHCNU6SURaJIRGVkm/TUkyyv64z2Ytvx3CBYCGWDAMGKANC1RS\n"+
	"jIe2BKn7FsEwi88kN730DPm3i9azjrup+1G/0fkyyPKoWr2n8D\n"+
	"oVKuLdJG5Afeny02XZ/YERO2KQZjW5GKWLUWP5eYE8h2F/hsMr\n"+
	"e2JEeN2JKdtBMlHcIMttZRBCl7XbURek153RR/lnbIimCwmj+p\n"+
	"HtkjmlQNJrCmCaV4eCi77JZD+makJY3aQALIjE0/2jVIwrgRNV\n"+
	"QuKK81CS/0t+21gDohL61hi7W6tjdhLtIgJq5+YhdSsJfakWTP\n"+
	"m8OCxJPrU3Hw8AiyqZgKiDxAWOnmrzSfrko8DGQ4f1degxMqag\n"+
	"HgDK+jSDY0RMlBvQhD+/9Rm94YbEy1Z2MpXuxtQWZldh6X+wb6\n"+
	"aCA9PGjocdO4ajY/Hjuoj5EEHedvVjAM9aNEWyd6yNiZPa3a6o\n"+
	"lHCQfYtTN+vD\n"+
	"\n"+
	"-----END CIPHER-----\n";

	@Override
	protected void setUp() throws Exception {
		MApi.get().getLogFactory().setDefaultLevel(LEVEL.TRACE);
		BouncyUtil.init();
	}
	
	public void testCreateCipher() throws ParseException, MException {
		System.out.println(">>> testCreateCipher");
		
		JavaRsaCipher cipher = new JavaRsaCipher();
		
		String text = contentBlock.toString();
		PemBlock enc = cipher.encode(PemUtil.toKey(pubKeyCipher), text);
		
		System.out.println(enc);

		String dec = cipher.decode(PemUtil.toKey(privKeyCipher), enc);
		
		assertEquals(text, dec);
		
	}
	
	public void testEmbeddedCipher() throws MException {
		System.out.println(">>> testEmbeddedCipher");
		
		SimplePemProcessContext context = new SimplePemProcessContext();

		PemBlockList list = new PemBlockList(privKeyCipher + cipherBlock);
		//System.out.println(list);
		
		CryptApiImpl api = new CryptApiImpl() {
			@Override
			public CipherProvider getCipher(String cipher) throws NotFoundException {
				if (cipher.equals("RSA-JCE"))
					return new JavaRsaCipher();
				throw new NotFoundException(cipher);
			}

		};
		api.processPemBlocks(context, list);

		assertEquals(contentBlock, context.getLastSecret().value() );
		
	}
	
	public void testCreateSign() throws MException {
		System.out.println(">>> testCreateSign");
		
		EccSigner signer = new EccSigner();

		String text = contentBlock.toString();
		PemBlock sign = signer.sign(PemUtil.toKey(privKeySign), text);
		
		System.out.println(sign);
		
		boolean valid = signer.validate(PemUtil.toKey(pubKeySign), text, sign);
		System.out.println(valid);
		assertTrue("Signer result is not valid",valid);
		
	}
	
	public void testSign() throws MException {
		System.out.println(">>> testSign");
		
//		EccSigner signer = new EccSigner();
//		boolean valid = signer.validate(PemUtil.toKey(pubKeySign), contentBlock.toString(), new PemBlockModel().parse(signature));
//		if (!valid) throw new MException("not valid");
		
		SimplePemProcessContext context = new SimplePemProcessContext();

		PemBlockList list = new PemBlockList(pubKeySign + signature + contentBlock);
		//System.out.println(list);
		
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
