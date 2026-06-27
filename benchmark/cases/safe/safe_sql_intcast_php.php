<?php
// SAFE: the id is hard-cast to int before interpolation. Trap: the value is
// concatenated into the SQL string (injection shape), but an (int) cast leaves
// no room for a payload.
function get_post_row($wpdb) {
    $id = (int) $_GET['id'];
    return $wpdb->get_row("SELECT * FROM {$wpdb->posts} WHERE ID = " . $id);
}
