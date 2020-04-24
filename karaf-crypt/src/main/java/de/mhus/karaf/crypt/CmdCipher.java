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
import de.mhus.lib.core.util.Base64;
import de.mhus.lib.core.util.Lorem;
import de.mhus.lib.core.vault.DefaultEntry;
import de.mhus.lib.core.vault.MVault;
import de.mhus.lib.core.vault.MVaultUtil;
import de.mhus.lib.core.vault.MutableVaultSource;
import de.mhus.lib.core.vault.VaultSource;
import de.mhus.osgi.api.karaf.AbstractCmd;
import de.mhus.osgi.api.services.MOsgi;
import de.mhus.osgi.crypt.api.CryptApi;
import de.mhus.osgi.crypt.api.cipher.CipherProvider;

@Command(scope = "crypt", name = "cipher", description = "Cipher Handling")
@Service
public class CmdCipher extends AbstractCmd {

    @Argument(
            index = 0,
            name = "cipher",
            required = true,
            description = "Selected cipher",
            multiValued = false)
    String cipher;

    @Argument(
            index = 1,
            name = "cmd",
            required = true,
            description =
                    "Command:\n"
                            + " list\n"
                            + " encrypt [key] [text]\n"
                            + " decrypt [key] [encoded]\n"
                            + " create\n"
                            + " test"
                            + " ",
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
            for (MOsgi.Service<CipherProvider> ref :
                    MOsgi.getServiceRefs(CipherProvider.class, null)) {
                System.out.println(ref.getReference().getProperty("cipher"));
            }
            return null;
        }

        CipherProvider prov = M.l(CryptApi.class).getCipher(cipher);

        switch (cmd) {
            case "encrypt":
                {
                    String text = parameters[1];
                    PemPub key = PemUtil.cipherPubFromString(parameters[0]);
                    PemBlock res = prov.encrypt(key, text);
                    if (!quiet) System.out.println(res);
                    return res;
                }
            case "decrypt":
                {
                    PemBlock text = findEncodedBlock(parameters[1]);
                    PemPriv key = PemUtil.cipherPrivFromString(parameters[0]);
                    String res = prov.decrypt(key, text, passphrase);
                    if (!quiet) System.out.println(res);
                    return res;
                }
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
                        if (verbose)
                            System.out.println(
                                    new PemKey(
                                            (PemKey) priv,
                                            false)); // need to create a new key without security
                                                     // restriction
                        System.out.println(pub);
                        if (verbose) System.out.println("Private: " + PemUtil.toLine(priv));
                        System.out.println();
                        System.out.println("Public : " + PemUtil.toLine(pub));
                    }

                    if (impPriv || impPubl) {
                        MVault vault = MVaultUtil.loadDefault();
                        VaultSource vaultSource = vault.getSource(impSource);
                        if (vaultSource == null) {
                            System.out.println("Vault Source not found " + impSource);
                        } else {
                            if (vaultSource instanceof MutableVaultSource) {

                                DefaultEntry pubEntry =
                                        new DefaultEntry(
                                                (UUID) pub.get(PemBlock.IDENT),
                                                prov.getName() + MVault.SUFFIX_CIPHER_PUBLIC_KEY,
                                                name,
                                                desc,
                                                pub.toString());
                                DefaultEntry privEntry =
                                        new DefaultEntry(
                                                (UUID) priv.get(PemBlock.IDENT),
                                                prov.getName() + MVault.SUFFIX_CIPHER_PRIVATE_KEY,
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
            case "test":
                {
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
                                        new PemKey((PemKey) keys.getPrivate()).getBytesBlock(),
                                        passphrase);
                        System.out.println("Unblowfished private key:");
                        System.out.println(Base64.encode(unblowfished));
                    }
                }
                break;
            default:
                System.out.println("Command unknown");
        }
        return null;
    }

    private static PemBlock findEncodedBlock(String text) throws Exception {

        PemBlockModel block = new PemBlockModel().parse(text);
        return block;
    }
}
