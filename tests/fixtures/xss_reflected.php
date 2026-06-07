<?php
// Reflected XSS: user input echoed without output encoding.
$name = $_GET['name'];
echo "Hello, $name!";
