<?php
// VULN: the IN() list is built from RAW request values with no integer cast.
function delete_selected_unsafe() {
    global $wpdb;
    $ids = (array) $_REQUEST['ids'];
    $wpdb->query("DELETE FROM posts WHERE ID IN( " . implode(',', $ids) . " )");
}
