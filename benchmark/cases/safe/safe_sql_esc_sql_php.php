<?php
// SAFE: the search term is escaped with esc_sql() before interpolation.
function search_safe($term) {
    global $wpdb;
    $term = esc_sql($term);
    return $wpdb->get_results("SELECT * FROM {$wpdb->posts} WHERE post_title LIKE '%{$term}%'");
}
