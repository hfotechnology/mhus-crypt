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

$publickey  = file_get_contents('key.pub');
$publickey = "-----BEGIN RSA PRIVATE KEY-----\n" . split("\n\n", $publickey)[1] . "\n-----END RSA PRIVATE KEY-----";
$privatekey = file_get_contents('key.sec.plain');
$privatekey = "-----BEGIN RSA PRIVATE KEY-----\n" . $privatekey . "\n-----END RSA PRIVATE KEY-----";

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