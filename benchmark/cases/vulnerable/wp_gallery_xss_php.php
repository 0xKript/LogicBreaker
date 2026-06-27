<?php
// VULN (gallery-plugin-style): a caption from the request is echoed unescaped.
add_action('wp_ajax_preview_caption', 'gal_preview');
function gal_preview() {
    echo "<figcaption>" . $_GET['caption'] . "</figcaption>";
}
