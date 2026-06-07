<?php
// prepared statement with bound parameter, output encoded before echo.
$stmt = $pdo->prepare("SELECT first_name FROM users WHERE user_id = ?");
$stmt->execute([$_GET['id']]);
$row = $stmt->fetch();
echo htmlspecialchars($row['first_name'], ENT_QUOTES);
