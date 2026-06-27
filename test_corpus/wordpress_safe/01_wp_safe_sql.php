<?php
/**
 * Safe WP 01: $wpdb->prepare with placeholders (correct).
 */
class My_Plugin {

    public function __construct() {
        add_action('wp_ajax_my_search', array($this, 'ajax_search'));
    }

    public function ajax_search() {
        if (!current_user_can('read')) {
            wp_die('forbidden', 403);
        }
        global $wpdb;
        $name = $_POST['name'];
        $sql = $wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}my_table WHERE name LIKE %s",
            '%' . $wpdb->esc_like($name) . '%'
        );
        $results = $wpdb->get_results($sql);
        wp_send_json($results);
    }
}
