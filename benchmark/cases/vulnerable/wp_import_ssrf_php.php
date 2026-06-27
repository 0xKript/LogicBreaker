<?php
// VULN (importer-plugin-style): server fetches a user-provided feed URL (SSRF).
add_action('wp_ajax_import_feed', 'imp_feed');
function imp_feed() {
    $url = $_POST['feed_url'];
    $data = file_get_contents($url);
    echo $data;
}
