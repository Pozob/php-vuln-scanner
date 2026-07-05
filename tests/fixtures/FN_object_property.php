<?php
// FALSE NEGATIVE: taint stored in an object property
$request = new stdClass();
$request->id = $_GET['id'];
mysql_query("SELECT * FROM users WHERE id = '" . $request->id . "'");
