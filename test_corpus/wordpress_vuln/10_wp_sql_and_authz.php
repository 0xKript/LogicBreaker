<?php
/**
 * Vuln WP 10: SQL injection via $wpdb->get_var with concatenation
 * and missing capability check (broken authz).
 */
class Admin_Ajax_Handler {

    public function __construct() {
        add_action('wp_ajax_delete_user', array($this, 'delete_user'));
    }

    public function delete_user() {
        // MISSING: current_user_can('delete_users') check
        global $wpdb;
        $id = $_POST['user_id'];
        $sql = "DELETE FROM {$wpdb->prefix}users WHERE ID = " . $id;
        $wpdb->query($sql);
        wp_send_json_success();
    }
}
