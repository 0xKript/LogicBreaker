<?php
// SAFE: the argument is wrapped with escapeshellarg(). Trap: a $_POST value
// reaches shell_exec (command-injection shape), but escaping quotes the value so
// it is treated as a single literal argument.
function thumbnail() {
    $file = escapeshellarg($_POST['file']);
    return shell_exec("convert " . $file . " /tmp/thumb.png");
}
