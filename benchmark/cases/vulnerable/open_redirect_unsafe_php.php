<?php
// VULN: redirects to a raw client-controlled URL with no validation.
function do_redirect() {
    $url = $_GET['next'];
    wp_redirect( $url );
    exit;
}
