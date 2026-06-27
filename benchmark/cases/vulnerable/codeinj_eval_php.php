<?php
// VULN: PHP eval of attacker input -- code injection (CWE-94).
function run($code) {
    eval($code);
}
?>
