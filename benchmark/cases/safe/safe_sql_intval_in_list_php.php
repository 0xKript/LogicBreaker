<?php
// SAFE: the IN() list is built from integer-cast IDs (array_map('intval', ...)),
// and the destructive action is gated by a capability + nonce check.
function bulk_delete_posts() {
    global $wpdb;
    if ( ! current_user_can('delete_posts') ) {
        wp_die('Not allowed');
    }
    check_admin_referer('bulk-delete');
    $ids = array_map('intval', (array) $_REQUEST['ids']);
    $wpdb->query("DELETE FROM {$wpdb->posts} WHERE ID IN( " . implode(',', $ids) . " )");
}
