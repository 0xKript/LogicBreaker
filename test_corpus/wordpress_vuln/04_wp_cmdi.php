<?php
/**
 * Vuln WP 04: Command Injection via system().
 */
class Backup_Plugin {

    public function __construct() {
        add_action('admin_post_do_backup', array($this, 'do_backup'));
    }

    public function do_backup() {
        $name = $_POST['backup_name'];
        system("tar -czf /tmp/" . $name . ".tar.gz /var/www/html");
        wp_die('done');
    }
}
