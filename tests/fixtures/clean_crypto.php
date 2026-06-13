<?php
$hash = password_hash($_POST['password'], PASSWORD_DEFAULT);
if (password_verify($_POST['password'], $stored_hash)) {
    $authenticated = true;
}
$reset_token = bin2hex(random_bytes(32));
$password = $_POST['password'];
