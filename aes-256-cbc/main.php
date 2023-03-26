<?php

$plaintext = "Ex dolore aliqua commodo do Lorem Lorem cillum dolor et. Ex dolore aliqua commodo do Lorem Lorem cillum dolor et. Ex dolore aliqua commodo do Lorem Lorem cillum dolor et. Ex dolore aliqua commodo do Lorem Lorem cillum dolor et.";
$enckey = 'G+KbPeShVkYp3s6v9y$B&E)H@McQfTjW';
$method = "aes-256-cbc";

// Must be exact 32 chars (256 bit)
$key = hash("sha256", $enckey, true);
echo "Password=" . bin2hex($key) . "\n";

// IV must be exact 16 chars (128 bit)
$iv = str_repeat(chr(0x0), 16);

// 1ZVlrDUbnGyfvH2/d72gPA==
$encrypted = base64_encode($iv.openssl_encrypt($plaintext, $method, $key, OPENSSL_RAW_DATA, $iv));

// HELLO WORLD
$decrypted = openssl_decrypt(base64_decode($encrypted), $method, $key, OPENSSL_RAW_DATA, $iv);

echo 'plaintext=' . $plaintext . "\n";
echo 'cipher=' . $method . "\n";
echo 'encrypted=' . $encrypted . "\n";
echo 'decrypted=' . $decrypted . "\n";