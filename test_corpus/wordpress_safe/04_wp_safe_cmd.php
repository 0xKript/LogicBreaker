<?php
/**
 * Safe WP 04: Command injection prevented via escapeshellarg + capability check.
 */
class Backup_Plugin {

    public function __construct() {
        add_action('admin_post_do_backup', array($this, 'do_backup'));
    }

    public function do_backup() {
        if (!current_user_can('manage_options')) {
            wp_die('forbidden', 403);
        }
        $name = escapeshellarg($_POST['backup_name']);
        system("tar -czf /tmp/" . $name . ".tar.gz /var/www/html");
        wp_die('done');
    }
}
