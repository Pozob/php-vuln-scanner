<?php
// FALSE NEGATIVE: Taint crosses function scope
function runQuery($sql) {
    return mysql_query($sql);
}
function currentPage() {
    return $_GET['page'];
}
runQuery("SELECT * FROM pages WHERE slug = '" . $_GET['slug'] . "'");
echo currentPage();
