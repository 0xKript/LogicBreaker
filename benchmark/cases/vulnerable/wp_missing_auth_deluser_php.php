<?php
// VULN (custom-plugin-style): destructive action with no capability/nonce check.
add_action('wp_ajax_nopriv_remove_member', 'plugin_remove_member');
function plugin_remove_member() {
    $user_id = intval($_POST['user_id']);
    wp_delete_user($user_id);
    echo 'deleted';
}
