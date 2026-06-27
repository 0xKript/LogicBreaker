<?php
// VULN: untrusted cookie passed to unserialize() (object injection).
function load_prefs() {
    $raw = $_COOKIE['prefs'];
    return unserialize($raw);
}
