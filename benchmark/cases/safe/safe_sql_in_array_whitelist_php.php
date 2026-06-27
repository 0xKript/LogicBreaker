<?php
// SAFE: the column comes from a fixed allow-list (in_array) before use.
function latest_by_field($field) {
    global $wpdb;
    if ( ! in_array($field, array('date', 'modified'), true) ) {
        return false;
    }
    return $wpdb->get_var("SELECT post_{$field} FROM $wpdb->posts ORDER BY post_{$field} DESC LIMIT 1");
}
