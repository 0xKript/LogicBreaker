<?php
// VULN (backup-plugin-style): a request value reaches the shell.
add_action('wp_ajax_run_backup', 'updraft_run_backup');
function updraft_run_backup() {
    $dir = $_POST['backup_dir'];
    exec("tar czf /tmp/backup.tgz " . $dir);
}
