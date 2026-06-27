<?php
// VULN (membership-plugin-style): the membership tier is trusted from the client.
add_action('wp_ajax_set_tier', 'mp_set_tier');
function mp_set_tier() {
    $role = $_POST['tier'];
    if ( $role === 'premium' ) {
        grant_premium_access(get_current_user_id());
    }
}
