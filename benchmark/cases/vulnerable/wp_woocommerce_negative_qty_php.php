<?php
// VULN (WooCommerce-style): client quantity drives the subtotal with no
// positivity check (negative quantity -> negative subtotal / refund abuse).
add_action('wp_ajax_recalc_line', 'recalc_cart_line');
function recalc_cart_line() {
    $quantity = intval($_POST['quantity']);
    $subtotal = $quantity * get_item_price($_POST['item']);
    WC()->cart->set_subtotal($subtotal);
}
