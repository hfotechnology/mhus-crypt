/**
 * Copyright 2018 Mike Hummel
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License at
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0
 *
 * <p>Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.mhus.karaf.crypt;

import java.io.File;
import java.util.Date;
import java.util.UUID;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.api.console.Session;

import de.mhus.lib.core.IProperties;
import de.mhus.lib.core.M;
import de.mhus.lib.core.MFile;
import de.mhus.lib.core.MProperties;
import de.mhus.lib.core.MString;
import de.mhus.lib.core.console.Console;
import de.mhus.lib.core.crypt.Blowfish;
import de.mhus.lib.core.crypt.pem.PemBlock;
import de.mhus.lib.core.crypt.pem.PemBlockModel;
import de.mhus.lib.core.crypt.pem.PemKey;
import de.mhus.lib.core.crypt.pem.PemPair;
import de.mhus.lib.core.crypt.pem.PemPriv;
import de.mhus.lib.core.crypt.pem.PemPub;
import de.mhus.lib.core.crypt.pem.PemUtil;
import de.mhus.lib.core.keychain.DefaultEntry;
import de.mhus.lib.core.keychain.MKeychain;
import de.mhus.lib.core.keychain.MKeychainUtil;
import de.mhus.lib.core.keychain.MutableVaultSource;
import de.mhus.lib.core.keychain.KeychainSource;
import de.mhus.lib.core.util.Lorem;
import de.mhus.osgi.api.karaf.AbstractCmd;
import de.mhus.osgi.api.services.MOsgi;
import de.mhus.osgi.crypt.api.CryptApi;
import de.mhus.osgi.crypt.api.signer.SignerProvider;

@Command(scope = "crypt", name = "signer", description = "Signer Handling")
@Service
public class CmdSigner extends AbstractCmd {

    @Argument(
            index = 0,
            name = "signer",
            required = true,
            description = "Selected signer",
            multiValued = false)
    String signer;

    @Argument(
            index = 1,
            name = "cmd",
            required = true,
            description =
                    "Command:\n list\n create\n sign [key] [text]\n validate [key] [sign] [text]",
            multiValued = false)
    String cmd;

    @Argument(
            index = 2,
            name = "paramteters",
            required = false,
            description = "Parameters",
            multiValued = true)
    String[] parameters;

    @Option(
            name = "-ip",
            aliases = {"--importPublic"},
            description = "Import Public Key into vault (don't forget to save vault)",
            required = false,
            multiValued = false)
    boolean impPubl = false;

    @Option(
            name = "-is",
            aliases = {"--importSecret"},
            description = "Import Private Key into vault (don't forget to save vault)",
            required = false,
            multiValued = false)
    boolean impPriv = false;

    @Option(
            name = "-s",
            aliases = {"--source"},
            description = "Define vault source other then 'default'",
            required = false,
            multiValued = false)
    String impSource = "default";

    @Option(
            name = "-d",
            aliases = {"--description"},
            description = "Descritpion of the key",
            required = false,
            multiValued = false)
    String desc = "";

    @Option(
            name = "-n",
            aliases = {"--name"},
            description = "Name of the key",
            required = false,
            multiValued = false)
    String name = "";

    @Option(
            name = "-p",
            aliases = {"--passphrase"},
            description = "Define a passphrase if required",
            required = false,
            multiValued = false)
    String passphrase = null;

    @Option(
            name = "-sp",
            aliases = {"--setPublic"},
            description = "Set Public Key into shell property",
            required = false,
            multiValued = false)
    String setPubl;

    @Option(
            name = "-ss",
            aliases = {"--setSecret"},
            description = "Set Private Key into shell property",
            required = false,
            multiValued = false)
    String setPriv;

    @Option(
            name = "-wp",
            aliases = {"--writePublic"},
            description = "Write Public Key to file",
            required = false,
            multiValued = false)
    String writePubl;

    @Option(
            name = "-ws",
            aliases = {"--writeSecret"},
            description = "Write Private Key tofile",
            required = false,
            multiValued = false)
    String writePriv;

    @Option(
            name = "-wsp",
            aliases = {"--writeSecretPassphrase"},
            description = "Set a extra passphrase for the secret key file",
            required = false,
            multiValued = false)
    String writePrivPassphrase = null;

    @Option(
            name = "-q",
            aliases = {"--quiet"},
            description = "Quiet mode",
            required = false,
            multiValued = false)
    boolean quiet = false;

    @Option(
            name = "-v",
            aliases = {"--verbose"},
            description = "Verbose will also print private key",
            required = false,
            multiValued = false)
    boolean verbose = false;

    @Reference private Session session;

    @Override
    public Object execute2() throws Exception {

        if (cmd.equals("list")) {
            for (MOsgi.Service<SignerProvider> ref :
                    MOsgi.getServiceRefs(SignerProvider.class, null)) {
                System.out.println(ref.getReference().getProperty("signer"));
            }
            return null;
        }

        SignerProvider prov = M.l(CryptApi.class).getSigner(signer);

        switch (cmd) {
            case "create":
                {
                    if ("".equals(passphrase)) {
                        System.out.print("Passphrase: ");
                        System.out.flush();
                        passphrase = Console.get().readPassword();
                        System.out.print("Verify: ");
                        System.out.flush();
                        String verify = Console.get().readPassword();
                        if (!passphrase.equals(verify)) {
                            System.out.println("Not the same - failed");
                            return null;
                        }
                    }

                    MProperties p = IProperties.explodeToMProperties(parameters);
                    if (passphrase != null) p.setString(CryptApi.PASSPHRASE, passphrase);
                    PemPair keys = prov.createKeys(p);
                    PemPriv priv = keys.getPrivate();
                    PemPub pub = keys.getPublic();

                    Date now = new Date();
                    if (priv instanceof PemKey) {
                        if (MString.isSet(desc))
                            ((PemKey) priv).setString(PemBlock.DESCRIPTION, desc);
                        ((PemKey) priv).setDate(PemBlock.CREATED, now);
                    }
                    if (pub instanceof PemKey) {
                        if (MString.isSet(desc))
                            ((PemKey) pub).setString(PemBlock.DESCRIPTION, desc);
                        ((PemKey) pub).setDate(PemBlock.CREATED, now);
                    }

                    if (!quiet) {
                        if (verbose) System.out.println(new PemKey((PemKey) priv, false));
                        System.out.println(pub);
                        if (verbose) System.out.println("Private: " + PemUtil.toLine(priv));
                        System.out.println();
                        System.out.println("Public : " + PemUtil.toLine(pub));
                    }

                    if (impPubl || impPriv) {
                        MKeychain vault = MKeychainUtil.loadDefault();
                        KeychainSource vaultSource = vault.getSource(impSource);
                        if (vaultSource == null) {
                            System.out.println("Vault Source not found " + impSource);
                        } else {
                            if (vaultSource instanceof MutableVaultSource) {

                                DefaultEntry pubEntry =
                                        new DefaultEntry(
                                                (UUID) pub.get(PemBlock.IDENT),
                                                prov.getName() + MKeychain.SUFFIX_SIGN_PUBLIC_KEY,
                                                name,
                                                desc,
                                                pub.toString());
                                DefaultEntry privEntry =
                                        new DefaultEntry(
                                                (UUID) priv.get(PemBlock.IDENT),
                                                prov.getName() + MKeychain.SUFFIX_SIGN_PRIVATE_KEY,
                                                name,
                                                desc,
                                                new PemKey((PemKey) priv, false).toString());

                                MutableVaultSource mvs = (MutableVaultSource) vaultSource;
                                if (impPubl) mvs.addEntry(pubEntry);
                                if (impPriv) mvs.addEntry(privEntry);

                                System.out.println("IMPORTED!");
                            } else {
                                System.out.println("Vault source is not writable " + impSource);
                            }
                        }
                    }
                    if (setPubl != null) session.put(setPubl, pub.toString());

                    if (setPriv != null)
                        session.put(setPriv, new PemKey((PemKey) priv, false).toString());

                    if (writePubl != null)
                        if (!MFile.writeFile(new File(writePubl), pub.toString()))
                            System.out.println("*** Write Failed: " + writePubl);

                    if (writePriv != null) {
                        String text = new PemKey((PemKey) priv, false).toString();
                        if (writePrivPassphrase != null) {
                            if (writePrivPassphrase.length() == 0) {
                                System.out.print("WS Passphrase: ");
                                System.out.flush();
                                writePrivPassphrase = Console.get().readPassword();
                                System.out.print("WS Verify: ");
                                System.out.flush();
                                String verify = Console.get().readPassword();
                                if (!writePrivPassphrase.equals(verify)) {
                                    System.out.println("Not the same - failed");
                                    return null;
                                }
                            }
                            text =
                                    "-----BEGIN CIPHER-----\nIdent: "
                                            + priv.getString(PemBlock.IDENT)
                                            + "\n\n"
                                            + Blowfish.encrypt(text, writePrivPassphrase)
                                            + "\n-----END CIPHER-----";
                        }
                        if (!MFile.writeFile(new File(writePriv), text))
                            System.out.println("*** Write Failed: " + writePriv);
                    }

                    return new Object[] {priv, pub};
                }
            case "sign":
                {
                    String text = parameters[1];
                    PemPriv key = PemUtil.signPrivFromString(parameters[0]);
                    PemBlock res = prov.sign(key, text, passphrase);
                    System.out.println(res);
                    return res;
                }
            case "validate":
                {
                    String text = parameters[2];
                    PemPub key = PemUtil.signPubFromString(parameters[0]);
                    PemBlock sign = findTextBlock(parameters[1]);

                    boolean res = prov.validate(key, text, sign);
                    System.out.println("Validate: " + res);
                    return res;
                }
            case "test":
                {
                    MProperties p = IProperties.explodeToMProperties(parameters);
                    if (passphrase != null) p.setString(CryptApi.PASSPHRASE, passphrase);
                    String text = Lorem.create(p.getInt("lorem", 1));

                    System.out.println(text);

                    PemPair keys = prov.createKeys(p);
                    System.out.println(keys.getPublic());
                    System.out.println(new PemKey((PemKey) keys.getPrivate(), false));

                    PemBlock sign = prov.sign(keys.getPrivate(), text, passphrase);
                    System.out.println(sign);

                    boolean valide = prov.validate(keys.getPublic(), text, sign);
                    System.out.println("Valide: " + valide);
                }
                break;
            default:
                System.out.println("Command unknown");
        }
        return null;
    }

    private PemBlock findTextBlock(String str) throws Exception {
        if (PemUtil.isPemBlock(str)) {
            return new PemBlockModel().parse(str);
        }
        return new PemBlockModel("", str);
    }
}
