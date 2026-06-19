<?php
// Wildcard CORS and disabled TLS certificate verification.
header('Access-Control-Allow-Origin: *');
$ch = curl_init('https://api.example.com');
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
