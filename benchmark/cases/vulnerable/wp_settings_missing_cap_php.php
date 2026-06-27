<?php
// VULN (membership-plugin-style): changes a user's role with no capability/nonce
// check (any logged-in user can elevate themselves to administrator).
add_action('wp_ajax_update_user_role', 'update_user_role');
function update_user_role() {
    $uid  = intval($_POST['uid']);
    $role = $_POST['role'];
    update_user_meta($uid, 'wp_capabilities', $role);
    wp_send_json_success();
}
