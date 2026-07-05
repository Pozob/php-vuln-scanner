<?php
// FALSE NEGATIVE: Together with FN_cross_file_input.php, the user_id is tainted
mysql_query("SELECT * FROM users WHERE id = '$user_id'");
