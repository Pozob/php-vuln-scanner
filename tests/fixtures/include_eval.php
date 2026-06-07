<?php
// File inclusion and code injection based on user input.
$page = $_GET['page'];
include($page . '.php');
eval($_POST['expression']);
