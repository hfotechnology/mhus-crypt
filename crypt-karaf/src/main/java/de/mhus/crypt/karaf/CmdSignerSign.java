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

import de.mhus.lib.core.M;
import de.mhus.lib.core.crypt.pem.PemBlock;
import de.mhus.lib.core.crypt.pem.PemPriv;
import de.mhus.lib.core.crypt.pem.PemUtil;
import de.mhus.osgi.api.karaf.AbstractCmd;
import de.mhus.crypt.api.CryptApi;
import de.mhus.crypt.api.signer.SignerProvider;

@Command(scope = "crypt", name = "signer", description = "Signer Handling")
@Service
public class CmdSignerSign extends AbstractCmd {

    @Argument(
            index = 0,
            name = "signer",
            required = true,
            description = "Selected signer",
            multiValued = false)
    String signer;

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
            name = "-p",
            aliases = {"--passphrase"},
            description = "Define a passphrase if required",
            required = false,
            multiValued = false)
    String passphrase = null;

    @Override
    public Object execute2() throws Exception {

        SignerProvider prov = M.l(CryptApi.class).getSigner(signer);

        PemPriv key = PemUtil.signPrivFromString(keyA);
        PemBlock res = prov.sign(key, text, passphrase);
        System.out.println(res);
        return res;
    }
}
