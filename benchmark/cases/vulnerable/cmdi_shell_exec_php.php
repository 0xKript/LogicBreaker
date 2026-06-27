<?php
// VULN: request value passed to the shell.
function convert() {
    $file = $_POST['file'];
    return shell_exec("convert " . $file . " /tmp/out.png");
}
