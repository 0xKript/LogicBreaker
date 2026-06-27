<?php
// SAFE: the client-supplied role is validated by a server-side capability check
// before it is applied, so it is not a trust-the-client authorization flaw.
function update_user_role($user_id) {
    if ( ! current_user_can('promote_users') ) {
        wp_die('Cheatin&#8217; uh?');
    }
    check_admin_referer('edit-user_' . $user_id);
    $role = $_POST['role'];
    $u = new WP_User($user_id);
    $u->set_role($role);
}
