<?php
// numeric cast sanitizes the SQL string traint, escapeshellarg the command.
$id = (int) $_GET['id'];
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = $id");
$host = escapeshellarg($_POST['host']);
system("ping -c 1 " . $host);
