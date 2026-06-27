<?php
// VULN (WooCommerce-style): discount amount comes from the client and is
// subtracted from the price with no bounds check (discount > price -> negative).
add_action('wp_ajax_apply_discount', 'wc_apply_discount');
function wc_apply_discount() {
    $discount = floatval($_POST['discount']);
    $price    = get_product_price($_POST['product_id']);
    $final    = $price - $discount;
    update_cart_total($final);
}
