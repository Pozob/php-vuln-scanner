<?php
// Command injection: user input flows into a shell command.
$host = $_POST['host'];
system("ping -c 1 " . $host);
