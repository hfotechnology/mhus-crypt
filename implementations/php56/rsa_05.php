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
include "Crypt/Blowfish.php";

$rsa = new Crypt_RSA();
$rsa->setEncryptionMode(CRYPT_RSA_ENCRYPTION_PKCS1);
$cipher = new Crypt_Blowfish(CRYPT_BLOWFISH_MODE_ECB);

$publickey  = file_get_contents('key.pub');
$publickey = "-----BEGIN RSA PRIVATE KEY-----\n" . split("\n\n", $publickey)[1] . "\n-----END RSA PRIVATE KEY-----";
$privatekeyplain = file_get_contents('key.sec.plain');

$privatekey = file_get_contents('key.sec');
$privatekey = split("\n\n",$privatekey)[1];
$privatekey = str_replace("\n", "", $privatekey);

$privatekey = base64_decode($privatekey);

$cipher->setKey('asdfghjkl');
$privatekey = $cipher->decrypt($privatekey);

$privatekey = base64_encode($privatekey);

$privatekey = "-----BEGIN RSA PRIVATE KEY-----\n" . $privatekey . "\n-----END RSA PRIVATE KEY-----";

echo "<PRE>";
echo $publickey;

echo "\n";

echo $privatekey;

echo "</PRE>";

$rsa->loadKey($publickey); // public key

$ciphertext = file_get_contents('cipher.txt');
$ciphertext = split("\n\n", $ciphertext)[1];
$ciphertext = str_replace("\n", "", $ciphertext);
$ciphertext = base64_decode($ciphertext);

$rsa->loadKey($privatekey); // private key

echo $rsa->decrypt($ciphertext);

?></html>