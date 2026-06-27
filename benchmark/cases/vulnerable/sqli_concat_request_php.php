<?php
// VULN: request value concatenated directly into SQL with no escaping/prepare.
function find_by_name() {
    global $wpdb;
    $name = $_GET['name'];
    return $wpdb->get_results("SELECT * FROM users WHERE display_name = '" . $name . "'");
}
