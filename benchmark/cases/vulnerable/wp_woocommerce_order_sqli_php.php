<?php
// VULN (WooCommerce-style): order id from request concatenated into a query.
add_action('wp_ajax_get_order', 'mystore_get_order');
function mystore_get_order() {
    global $wpdb;
    $order_id = $_GET['order_id'];
    $row = $wpdb->get_row("SELECT * FROM {$wpdb->prefix}wc_orders WHERE id = " . $order_id);
    wp_send_json($row);
}
