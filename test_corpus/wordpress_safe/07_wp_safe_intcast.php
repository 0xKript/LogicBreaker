<?php
/**
 * Adversarial safe WP: $wpdb->prepare with %d for integer (correct).
 */
class Counter_Plugin {

    public function get_count() {
        if (!current_user_can('read')) {
            wp_die('forbidden', 403);
        }
        global $wpdb;
        $id = (int) $_GET['id'];  // explicit int cast = sanitiser
        $sql = $wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->prefix}views WHERE post_id = %d",
            $id
        );
        return $wpdb->get_var($sql);
    }
}
