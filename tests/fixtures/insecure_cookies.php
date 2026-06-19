<?php
// Cookies and session configured insecure
setcookie('auth', $token, time() + 3600);
session_set_cookie_params(['lifetime' => 3600, 'path' => '/']);
ini_set('session.cookie_httponly', '0');
session_start();
