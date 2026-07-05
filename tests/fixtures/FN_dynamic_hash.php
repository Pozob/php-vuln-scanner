<?php
// FALSE NEGATIVE: Dynamically invoked function via string, and hash algorithm as parameter
$md5 = 'md5';
$hash = $md5($_POST['password']);
$hash2 = hash('md5', $_POST['password']);
