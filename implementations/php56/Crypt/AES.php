<?php
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
/**
 * Include Crypt_Rijndael
 */
if (!class_exists('Crypt_Rijndael')) {
    include_once 'Rijndael.php';
}

/**#@+
 * @access public
 * @see self::encrypt()
 * @see self::decrypt()
 */
/**
 * Encrypt / decrypt using the Counter mode.
 *
 * Set to -1 since that's what Crypt/Random.php uses to index the CTR mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Counter_.28CTR.29
 */
define('CRYPT_AES_MODE_CTR', CRYPT_MODE_CTR);
/**
 * Encrypt / decrypt using the Electronic Code Book mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Electronic_codebook_.28ECB.29
 */
define('CRYPT_AES_MODE_ECB', CRYPT_MODE_ECB);
/**
 * Encrypt / decrypt using the Code Book Chaining mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher-block_chaining_.28CBC.29
 */
define('CRYPT_AES_MODE_CBC', CRYPT_MODE_CBC);
/**
 * Encrypt / decrypt using the Cipher Feedback mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher_feedback_.28CFB.29
 */
define('CRYPT_AES_MODE_CFB', CRYPT_MODE_CFB);
/**
 * Encrypt / decrypt using the Cipher Feedback mode.
 *
 * @link http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Output_feedback_.28OFB.29
 */
define('CRYPT_AES_MODE_OFB', CRYPT_MODE_OFB);
/**#@-*/

/**
 * Pure-PHP implementation of AES.
 *
 * @package Crypt_AES
 * @author  Jim Wigginton <terrafrost@php.net>
 * @access  public
 */
class Crypt_AES extends Crypt_Rijndael
{
    /**
     * The namespace used by the cipher for its constants.
     *
     * @see Crypt_Base::const_namespace
     * @var string
     * @access private
     */
    var $const_namespace = 'AES';

    /**
     * Dummy function
     *
     * Since Crypt_AES extends Crypt_Rijndael, this function is, technically, available, but it doesn't do anything.
     *
     * @see Crypt_Rijndael::setBlockLength()
     * @access public
     * @param int $length
     */
    function setBlockLength($length)
    {
        return;
    }

    /**
     * Sets the key length
     *
     * Valid key lengths are 128, 192, and 256.  If the length is less than 128, it will be rounded up to
     * 128.  If the length is greater than 128 and invalid, it will be rounded down to the closest valid amount.
     *
     * @see Crypt_Rijndael:setKeyLength()
     * @access public
     * @param int $length
     */
    function setKeyLength($length)
    {
        switch ($length) {
            case 160:
                $length = 192;
                break;
            case 224:
                $length = 256;
        }
        parent::setKeyLength($length);
    }

    /**
     * Sets the key.
     *
     * Rijndael supports five different key lengths, AES only supports three.
     *
     * @see Crypt_Rijndael:setKey()
     * @see setKeyLength()
     * @access public
     * @param string $key
     */
    function setKey($key)
    {
        parent::setKey($key);

        if (!$this->explicit_key_length) {
            $length = strlen($key);
            switch (true) {
                case $length <= 16:
                    $this->key_length = 16;
                    break;
                case $length <= 24:
                    $this->key_length = 24;
                    break;
                default:
                    $this->key_length = 32;
            }
            $this->_setEngine();
        }
    }
}
