<?php
// Using the old msql API: user input flows into a raw SQL string.
$id = $_GET['id'];
$query = "SELECT first_name FROM users WHERE user_id = '$id'";
$result = mysql_query($query) or die(mysql_error());
