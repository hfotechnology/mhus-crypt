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
package de.mhus.karaf.crypt;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;

import de.mhus.lib.core.M;
import de.mhus.lib.core.crypt.pem.PemBlock;
import de.mhus.lib.core.crypt.pem.PemPub;
import de.mhus.lib.core.crypt.pem.PemUtil;
import de.mhus.osgi.api.karaf.AbstractCmd;
import de.mhus.osgi.crypt.api.CryptApi;
import de.mhus.osgi.crypt.api.cipher.CipherProvider;

@Command(scope = "crypt", name = "cipher-encrypt", description = "Cipher encrypt plain")
@Service
public class CmdCipherEncrypt extends AbstractCmd {

    @Argument(
            index = 0,
            name = "cipher",
            required = true,
            description = "Selected cipher",
            multiValued = false)
    String cipher;

    @Argument(index = 1, name = "key", required = true, description = "Key", multiValued = false)
    String keyA;

    @Argument(
            index = 2,
            name = "plain",
            required = true,
            description = "Plain text",
            multiValued = false)
    String text;

    @Option(
            name = "-q",
            aliases = {"--quiet"},
            description = "Quiet mode",
            required = false,
            multiValued = false)
    boolean quiet = false;

    @Override
    public Object execute2() throws Exception {

        CipherProvider prov = M.l(CryptApi.class).getCipher(cipher);

        PemPub key = PemUtil.cipherPubFromString(keyA);
        PemBlock res = prov.encrypt(key, text);
        if (!quiet) System.out.println(res);
        return res;
    }
}
