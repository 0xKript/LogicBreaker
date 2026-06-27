<?php
// VULN (cache-plugin-style): deletes a cache file at a request-controlled path.
add_action('wp_ajax_purge_file', 'cache_purge_file');
function cache_purge_file() {
    $file = $_POST['cache_file'];
    unlink(WP_CONTENT_DIR . '/cache/' . $file);
    readfile(WP_CONTENT_DIR . '/cache/' . $file);
}
