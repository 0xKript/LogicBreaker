<?php
function backup($dir) {
    // VULN: command injection
    system("tar -czf backup.tar.gz " . $dir);
}
