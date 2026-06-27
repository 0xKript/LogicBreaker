<?php
// VULN (CF7-style): builds a file path from a request value and reads it.
add_action('wp_ajax_nopriv_download_attachment', 'cf7_download');
function cf7_download() {
    $name = $_GET['filename'];
    $path = WP_CONTENT_DIR . '/uploads/cf7/' . $name;
    readfile($path);
}
