<?php
// Deprecated crypto API and a broken cipher
$ciphertext = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_ECB);
$encrypted = openssl_encrypt($data, 'des-ecb', $key);
