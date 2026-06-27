<?php
/**
 * Safe WP 06: open redirect prevented via wp_validate_redirect.
 */
class Login_Plugin {

    public function handle_login() {
        $next = $_GET['redirect_to'];
        $safe = wp_validate_redirect($next, home_url());
        wp_safe_redirect($safe);
        exit;
    }
}
