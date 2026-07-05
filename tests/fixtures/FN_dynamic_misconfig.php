<?php
// FALSE NEGATIVE: configuration values that are set via variables and not literals are not found
$debug = getenv('APP_DEBUG');
ini_set('display_errors', $debug);
$cors = 'Access-Control-Allow-Origin: *';
header($cors);
$secure = false;
$httponly = false;
setcookie('auth', $token, 0, '/', '', $secure, $httponly);
