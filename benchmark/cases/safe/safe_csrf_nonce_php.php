<?php
// SAFE: the state-changing action verifies a nonce AND a capability. Trap: it is
// a POST handler that mutates data (CSRF shape), but the nonce check blocks
// cross-site requests and the capability check enforces authorization.
add_action('admin_post_save_settings', 'save_plugin_settings');
function save_plugin_settings() {
    if ( ! current_user_can('manage_options') ) {
        wp_die('forbidden');
    }
    check_admin_referer('save_settings_action', 'save_settings_nonce');
    update_option('my_setting', sanitize_text_field($_POST['value']));
}
