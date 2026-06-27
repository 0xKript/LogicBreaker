<?php
/**
 * Hidden WP: SQL injection via $wpdb->get_results with sprintf concatenation.
 * Subtle: looks safe due to sprintf but %s is NOT a prepared statement.
 */
class Stats_Plugin {

    public function get_stats() {
        global $wpdb;
        $period = $_GET['period'];
        // sprintf %s is NOT a prepared statement -- this is SQL injection
        $sql = sprintf(
            "SELECT COUNT(*) FROM {$wpdb->prefix}stats WHERE period = '%s'",
            $period
        );
        return $wpdb->get_results($sql);
    }
}
