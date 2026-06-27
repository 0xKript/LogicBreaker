<?php
// VULN (Elementor-style): fetches a user-supplied URL server-side (SSRF).
add_action('wp_ajax_import_template', 'el_import_template');
function el_import_template() {
    $url = $_POST['template_url'];
    $body = wp_remote_retrieve_body(wp_remote_get($url));
    echo curl_exec(curl_init($url));
}
