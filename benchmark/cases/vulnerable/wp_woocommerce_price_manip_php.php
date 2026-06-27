<?php
// VULN (WooCommerce-style): line total computed from a client-supplied price
// with no server-side bounds/catalogue check (price tampering).
add_action('wp_ajax_apply_quote', 'apply_custom_price');
function apply_custom_price() {
    $price = floatval($_POST['custom_price']);
    $quantity = intval($_POST['qty']);
    $line_total = $price * $quantity;
    update_cart_total($line_total);
}
