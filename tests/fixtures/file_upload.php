<?php
// The client controls the uploaded file name, so $_FILES isa taint source
$filename = $_FILES['upload']['name'];
mysql_query("INSERT INTO uploads (name) VALUES ('$filename')");
