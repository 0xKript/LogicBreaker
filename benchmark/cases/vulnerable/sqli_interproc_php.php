<?php
function run_query($q) {
    mysqli_query($GLOBALS['db'], $q);
}
function dispatch($x) {
    run_query($x);
}
function handle() {
    $u = $_GET["name"];
    dispatch("SELECT * FROM users WHERE name = '" . $u . "'");
}
