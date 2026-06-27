<?php
// SAFE: wp_safe_redirect() validates the destination against allowed hosts.
function handle_save() {
    if ( isset($_POST['save']) ) {
        wp_safe_redirect( $_POST['_wp_http_referer'] );
        exit;
    }
}
