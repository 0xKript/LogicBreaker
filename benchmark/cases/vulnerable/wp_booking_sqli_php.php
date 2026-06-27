<?php
// VULN (booking-plugin-style): availability query concatenates a request date.
add_action('wp_ajax_check_availability', 'bk_check');
function bk_check() {
    global $wpdb;
    $date = $_GET['date'];
    $rows = $wpdb->get_results("SELECT * FROM {$wpdb->prefix}bookings WHERE day = '" . $date . "'");
    wp_send_json($rows);
}
