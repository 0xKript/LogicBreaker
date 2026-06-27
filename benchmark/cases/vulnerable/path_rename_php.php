<?php
// VULN: path traversal -- renames a file to a user-controlled destination path.
function move_report() {
    $dest = $_GET['dest'];
    rename("/tmp/report.tmp", "/var/reports/" . $dest);   // ../ escapes the directory
}
