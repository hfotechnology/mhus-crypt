/*
 * Copyright (C) 2020 Mike Hummel (mh@mhus.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
keys = rsa01.createKeys({});
e = rsa01.encrypt(keys[0],"HelloWorld");
rsa01.decrypt(keys[1],e);
 */

var rsa01 = {

	encrypt : function(pubKey, content) {
		var pem = new PemBlock(pubKey);
		var block = pem.getBlock();
		var pki = forge.pki;
		var block = "-----BEGIN PUBLIC KEY-----\n"+block+"\n-----END PUBLIC KEY-----";
		var publicKey = pki.publicKeyFromPem(block);
		var contentParts = content.match(/[\s\S]{1,50}/g);
		var contentLength = contentParts.length;
		var encrypted = null;
		for (var i = 0; i < contentLength; i++) {
			var encryptedPart = publicKey.encrypt(contentParts[i], 'RSA-OAEP', {
				  md: forge.md.sha256.create(),
				  mgf1: {
				    md: forge.md.sha1.create()
				  }
				});
			if (encrypted != null) 
				encrypted = encrypted + "\r" + base64.encode(encryptedPart);
			else
				encrypted = base64.encode(encryptedPart);
		}
		var cPem = new PemBlock();
		cPem.block = encrypted;
		cPem.setName("CIPHER");
		cPem.list.Method = this.getName();
		cPem.list.PublicKey = pem.list.Ident;
		cPem.list.PrivateKey = pem.list.PrivateKey;
		cPem.list.Created = new Date().toString();

		return cPem.toString();
	},

	encryptBc : function(pubKey, content) {
		var pem = new PemBlock(pubKey);
		var block = pem.getBlock();
		var pki = forge.pki;
		var block = "-----BEGIN PUBLIC KEY-----\n"+block+"\n-----END PUBLIC KEY-----";
		var publicKey = pki.publicKeyFromPem(block);
		var keyLength = pem.list.Length;
		if (!keyLength) keyLength = 1024;
		var blockSize = keyLength == 512 ? 53 : 117;
		contentLength = content.length;
		var encrypted = "";
		for (var i = 0; i < contentLength; i=i+blockSize) {
			var encryptedPart = publicKey.encrypt(content.slice(i, i+blockSize), 'RSAES-PKCS1-V1_5');
			encrypted = encrypted+encryptedPart;
		}
		var cPem = new PemBlock();
		cPem.block = base64.encode(encrypted);
		cPem.setName("CIPHER");
		cPem.list.Method = "RSA-BC-01";
		cPem.list.PublicKey = pem.list.Ident;
		cPem.list.PrivateKey = pem.list.PrivateKey;
		cPem.list.Created = new Date().toString();

		return cPem.toString();
	},
	
	decrypt : function(privKey, encrypted, passphrase) {
		var pPem = new PemBlock(privKey);
		var block = pPem.getBlock();
		if (pPem.list.Encrypted) {
			if (pPem.list.Encrypted == 'blowfish') {
				block = this.decryptBlowfish(block, passphrase);
			} else
				throw new Error("Unknown passphraseEncryptionType");
		}
		var pki = forge.pki;
		var block = "-----BEGIN RSA PRIVATE KEY-----\n"+block+"\n-----END RSA PRIVATE KEY-----";
		var privateKey = pki.privateKeyFromPem(block);

		var ePem = new PemBlock(encrypted);
		encrypted = ePem.getBlock();
		var encryptedParts = encrypted.split("\r");
		var encryptedLength = encryptedParts.length;
		var content = "";
		for (var i = 0; i < encryptedLength; i++) {
			var contentPart = privateKey.decrypt(base64.decode(encryptedParts[i]), 'RSA-OAEP', {
				md: forge.md.sha256.create(),
				mgf1: {
					md: forge.md.sha1.create()
				}
			});
			content = content + contentPart;
		}
		return content;
	},
	
	decryptBc : function(privKey, encrypted, passphrase) {
		var pPem = new PemBlock(privKey);
		var block = pPem.getBlock();
		if (pPem.list.Encrypted) {
			if (pPem.list.Encrypted == 'blowfish') {
				block = this.decryptBlowfish(block, passphrase);
			} else
				throw new Error("Unknown passphraseEncryptionType");
		}
		var pki = forge.pki;
		var block = "-----BEGIN RSA PRIVATE KEY-----\n"+block+"\n-----END RSA PRIVATE KEY-----";
		var privateKey = pki.privateKeyFromPem(block);

		var ePem = new PemBlock(encrypted);
		encrypted = ePem.getBlock();
		var encryptedBin = base64.decode(encrypted);
		var encryptedLength = encryptedBin.length;
		var content = "";
		var keyLength = pPem.list.Length;
		if (!keyLength) keyLength = 1024; // TODO calculate from block size
		var blockSize = Math.max(keyLength / 1024 * 128, 64);
		for (var i = 0; i < encryptedLength; i=i+blockSize) {
			// RSA/ECB/PKCS1Padding
			var contentPart = privateKey.decrypt(encryptedBin.slice(i, i+blockSize), 'RSAES-PKCS1-V1_5');
			content = content + contentPart.replace(/\u0000*/, ''); // TODO maybe not ok
		}
		return content;
	},
	
	createKeys : function(properties) {
		var keylen = properties.length ? properties.length : 1024;
		var passphrase = properties.passphrase ? properties.passphrase : null;
		var created = new Date().toString();
		var identPrivateKey = this._uuidv4();
		var identPublicKey = this._uuidv4();
		var keys = forge.pki.rsa.generateKeyPair(keylen);
		var privateKeyP12Pem = forge.pki.privateKeyToPem(keys.privateKey);
		var publicKeyP12Pem = forge.pki.publicKeyToPem(keys.publicKey);

		var pem = new PemBlock(privateKeyP12Pem);
		var block = pem.getBlock(); // .replace(/\r/g,'')
		
		//--
		var b = "-----BEGIN RSA PRIVATE KEY-----\n"+block+"\n-----END RSA PRIVATE KEY-----";
		var xprivateKey = forge.pki.privateKeyFromPem(b);
		
		//--
		var ppEncType = null;
		if (passphrase) {
			ppEncType = properties.passphraseEncryptionType ? properties.passphraseEncryptionType : "blowfish";
			if (ppEncType == "blowfish") {
				block = this.encryptBlowfish(block, passphrase);
			} else
				throw new Error("Unknown passphraseEncryptionType");
		}
		var pem = new PemBlock();
		pem.block = block;
		pem.name='PRIVATE KEY';
		pem.list.Ident=identPrivateKey;
		pem.list.Format='PKCS#8';
		pem.list.PublicKey=identPublicKey;
		pem.list.Length=keylen;
		if (ppEncType != null) {
			pem.list.Encrypted=ppEncType;
		}
		pem.list.Method=this.getName();
		pem.list.Created=created;
		privateKeyP12Pem=pem.toString();

		var pem = new PemBlock(publicKeyP12Pem);
		pem.block = pem.block.replace(/\r/g,'');
		
		pem.name='PUBLIC KEY';
		pem.list.Ident=identPublicKey;
		pem.list.Format='X.509';
		pem.list.PrivateKey=identPrivateKey;
		pem.list.Length=keylen;
		pem.list.Method=this.getName();
		pem.list.Created=created;
		publicKeyP12Pem=pem.toString();

		return [publicKeyP12Pem, privateKeyP12Pem];
	},
	
	pepper : function(data) {
		var p = "";
		var rounds = Math.floor(Math.random()*(10)+1);
		for (var i = 0; i < rounds; i++)
			p = p + Math.random().toString(36).substring(2);
		data = p + '+' + data;
		return data;
	},
	unpepper : function(data) {
		var p = data.indexOf("+");
		if (p > 0) {
			data = data.substring(p+1);
		}
		return data;
	},
	getName : function() {
		return "RSA-JS-01";
	},
	decryptBlowfish : function(code, passphrase) {
		if (!passphrase) passphrase = "";
		return base64.encode(
				blowfish.decrypt(
						code, passphrase, {cipherMode: 0, outputType: 0})
						);
	},
	encryptBlowfish : function(text, passphrase) {
		if (!passphrase) passphrase = "";
		return blowfish.encrypt( base64.decode(text), passphrase, {cipherMode: 0, outputType: 0});
	},

	_uuidv4 : function() {
	  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
	    var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
	    return v.toString(16);
	  });
	},

};