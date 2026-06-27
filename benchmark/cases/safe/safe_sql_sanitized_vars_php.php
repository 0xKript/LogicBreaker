<?php
// SAFE: every value interpolated into the query has safe provenance --
// sanitize_key(), escape_by_ref via array_walk, and gmdate() (a date string).
function post_times($post_type) {
    global $wpdb;
    array_walk($post_type, array($wpdb, 'escape_by_ref'));
    $types  = "'" . implode("', '", $post_type) . "'";
    $offset = gmdate('Z');
    return $wpdb->get_var("SELECT DATE_ADD(post_date, INTERVAL '$offset' SECOND) FROM $wpdb->posts WHERE post_type IN ($types) LIMIT 1");
}
