<?php
/**
 * Vuln WP 09: Open Redirect via wp_redirect with user input.
 */
class Login_Plugin {

    public function handle_login() {
        $next = $_GET['redirect_to'];
        wp_redirect($next);
        exit;
    }
}
