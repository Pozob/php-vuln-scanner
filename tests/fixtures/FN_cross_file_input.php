<?php
// FALSE NEGATIVE: Together with FN_cross_file_query.php, the tainted variabel is given to
// a sql query
$user_id = $_GET['id'];
include 'FN_cross_file_query.php';
