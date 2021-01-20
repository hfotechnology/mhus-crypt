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
<html><?php
ini_set('display_startup_errors', 1);
ini_set('display_errors', 1);
error_reporting(-1);

// https://stackoverflow.com/questions/26369558/how-to-use-a-pkcs8-encoded-private-key-in-php
// http://phpseclib.sourceforge.net/rsa/intro.html
// http://phpseclib.sourceforge.net/rsa/examples.html#convert

include "Crypt/RSA.php";

$rsa = new Crypt_RSA();

// $rsa->setPrivateKeyFormat(CRYPT_RSA_PRIVATE_FORMAT_PKCS8);
// $rsa->setPublicKeyFormat(CRYPT_RSA_PUBLIC_FORMAT_PKCS8);

// extract($rsa->createKey());

// echo $privatekey . "\r\n\r\n";
// echo $publickey;

$publickey  = '-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDPzSKj+3L1KQ
Z0+uwLGxHSJyBfSpRYpJYMxBeFD9bzdcE0px7lc0A/wzWAbWEb
0DoOrK/rrBldg657AJ9ZYGrcJTVd3rYUzkj7C37/BwP/y6H01t
mRmdA+ArEGQVoI5h0aaVWG/tg1IlWRtiD6OElgIbX5sDblTA1h
6uaChcWrlQIDAQAB
-----END PUBLIC KEY-----';

$privatekey='-----BEGIN RSA PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAM
/NIqP7cvUpBnT67AsbEdInIF9KlFiklgzEF4UP1vN1wTSnHuVz
QD/DNYBtYRvQOg6sr+usGV2DrnsAn1lgatwlNV3ethTOSPsLfv
8HA//LofTW2ZGZ0D4CsQZBWgjmHRppVYb+2DUiVZG2IPo4SWAh
tfmwNuVMDWHq5oKFxauVAgMBAAECgYBSbhA4tk0ivRRnoQWzXh
iSoZyw0DfKdfdjtwGRcfgVeXebuFOEN1ScNoZpnHnx+4acPZpH
RWyGcO7sshGD9cBNPqP2hvp9d+YvH3JOczO+D3xnSlfnMii0XR
7eTaF32+T73rB4G/cQ8+Gp9IeoZwrj60sa4WZUrOuvUeH4NQEI
IQJBAOgi0iM973ZntKbeJBoEeIRX0nYIz5qGytXyeZJPFegUhX
0Ljf9wQD9x8Zwm+8AhHmGyFasb1Cw/u4j7ATOnl90CQQDlKeRg
0KOZ9W6h+4o2XlDcL5aUJcEZulWGvIbUXcKUWBdQbrwMbCb/6b
PpjScQFpTR6tZla4S9IULKkHJGPUMZAkEA42sBra8Gw1xUGkp0
2dxZaWZUdHirUnsNik6TlafPEV/RazD/uylwd/ecOVvjtVV82z
9JhSmtUnBZvJgTlFRzLQJBALej2HWU/GWV/nAkCOAEuLuaDwrt
Lk8VuQ/d6BYqhJEn/pbgBiXWTXJqr1gLWzBTSDLoA6MGhDqjes
ik9E5BLZECQFDVDPjE10MbqVvkFMRPcPJvECBn44TFeg2MseEA
kQHVgbfuvVgZ3eX2nc3uzqbflCfgi1F1lINBeoJQIb4eexQ=
-----END RSA PRIVATE KEY-----';

echo "<PRE>";
echo $publickey;

echo "\n";

echo $privatekey;

echo "</PRE>";

$rsa->loadKey($publickey); // public key

$plaintext = 'Lorem Lorem Lorem';

//$rsa->setEncryptionMode(CRYPT_RSA_ENCRYPTION_OAEP);
$ciphertext = $rsa->encrypt($plaintext);

$rsa->loadKey($privatekey); // private key

echo $rsa->decrypt($ciphertext);

?></html>