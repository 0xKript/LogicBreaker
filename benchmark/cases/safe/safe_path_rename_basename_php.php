<?php
// SAFE: basename() strips any directory components before the rename, so the
// destination stays inside the reports directory. Trap: renames to a path built
// from $_GET (path-traversal shape), but basename() neutralises `../`.
function move_report() {
    $dest = basename($_GET['dest']);
    rename("/tmp/report.tmp", "/var/reports/" . $dest);
}
