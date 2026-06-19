<?php
// safe cookies, session, CORS, and TLS configuration.
ini_set('display_errors', '0');
setcookie('auth', $token, ['expires' => 3600, 'secure' => true, 'httponly' => true]);
session_set_cookie_params(['secure' => true, 'httponly' => true]);
header('Access-Control-Allow-Origin: https://app.example.com');
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
