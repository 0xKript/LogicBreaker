<?php
/**
 * Vuln WP 01: SQL Injection via $wpdb->query with concatenation.
 * Typical WordPress plugin pattern: handler registered via add_action.
 */
class My_Plugin {

    public function __construct() {
        add_action('wp_ajax_my_search', array($this, 'ajax_search'));
        add_action('wp_ajax_nopriv_my_search', array($this, 'ajax_search'));
    }

    public function ajax_search() {
        global $wpdb;
        $name = $_POST['name'];
        $sql = "SELECT * FROM {$wpdb->prefix}my_table WHERE name LIKE '%" . $name . "%'";
        $results = $wpdb->get_results($sql);
        wp_send_json($results);
    }
}
