<?php
// Weak security hashing
$hash = md5($_POST['password']);
$query = "SELECT * FROM users WHERE password = '$hash'";
$legacy = crypt($_POST['password']);
if (sha1($_GET['token']) === $stored_password_hash) {
    $authenticated = true;
}
