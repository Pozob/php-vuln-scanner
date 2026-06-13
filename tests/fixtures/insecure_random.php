<?php
// Insecure randomness
$reset_token = uniqid(rand(), true);
setcookie('reset', $reset_token);
