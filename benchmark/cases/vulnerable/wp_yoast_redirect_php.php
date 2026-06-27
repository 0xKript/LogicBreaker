<?php
// VULN (SEO-plugin-style): redirects to a raw client-controlled target.
add_action('template_redirect', 'seo_handle_redirect');
function seo_handle_redirect() {
    if ( isset($_GET['redirect_to']) ) {
        $target = $_GET['redirect_to'];
        wp_redirect($target);
        exit;
    }
}
