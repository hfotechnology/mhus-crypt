/**
 * Copyright (C) 2019 Mike Hummel (mh@mhus.de)
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
package de.mhus.crypt.karaf;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;

import de.mhus.lib.core.IProperties;
import de.mhus.lib.core.M;
import de.mhus.lib.core.MProperties;
import de.mhus.lib.core.MString;
import de.mhus.lib.core.crypt.Blowfish;
import de.mhus.lib.core.crypt.pem.PemBlock;
import de.mhus.lib.core.crypt.pem.PemKey;
import de.mhus.lib.core.crypt.pem.PemPair;
import de.mhus.lib.core.util.Base64;
import de.mhus.lib.core.util.Lorem;
import de.mhus.osgi.api.karaf.AbstractCmd;
import de.mhus.crypt.api.CryptApi;
import de.mhus.crypt.api.cipher.CipherProvider;

@Command(scope = "crypt", name = "cipher-test", description = "Cipher test")
@Service
public class CmdCipherTest extends AbstractCmd {

    @Argument(
            index = 0,
            name = "cipher",
            required = true,
            description = "Selected cipher",
            multiValued = false)
    String cipher;

    @Argument(
            index = 1,
            name = "paramteters",
            required = false,
            description = "Parameters",
            multiValued = true)
    String[] parameters;

    @Option(
            name = "-p",
            aliases = {"--passphrase"},
            description = "Define a passphrase if required",
            required = false,
            multiValued = false)
    String passphrase = null;

    @Override
    public Object execute2() throws Exception {

        CipherProvider prov = M.l(CryptApi.class).getCipher(cipher);

        MProperties p = IProperties.explodeToMProperties(parameters);
        if (passphrase != null) p.setString(CryptApi.PASSPHRASE, passphrase);
        String text = p.getString("text", null);
        if (text == null) text = Lorem.create(p.getInt("lorem", 2));
        System.out.println(text);

        PemPair keys = prov.createKeys(p);
        System.out.println(keys.getPublic());
        System.out.println(new PemKey((PemKey) keys.getPrivate(), false));

        PemKey pubKey = new PemKey(keys.getPublic());

        p.remove("text");
        pubKey.putAll(p); // put cmd parameters e.g. AesLength

        PemBlock encoded = prov.encrypt(pubKey, text);
        System.out.println(encoded);
        String decoded = prov.decrypt(keys.getPrivate(), encoded, passphrase);
        System.out.println(decoded);
        boolean valid = text.equals(decoded);
        System.out.println("Valide: " + valid);
        // unblowfish
        if (MString.isSet(passphrase)) {
            System.out.println();
            byte[] unblowfished =
                    Blowfish.decrypt(
                            new PemKey((PemKey) keys.getPrivate()).getBytesBlock(), passphrase);
            System.out.println("Unblowfished private key:");
            System.out.println(Base64.encode(unblowfished));
        }

        return null;
    }
}
