<?php
// FALSE NEGATIVE: The tainted value is safed in Database and later used in an echo sink
$name = mysqli_real_escape_string($connection, $_POST['name']);
mysqli_query($connection, "INSERT INTO comments (author) VALUES ('$name')");

$result = mysqli_query($connection, "SELECT author FROM comments");
$row = mysqli_fetch_assoc($result);
echo $row['author'];
