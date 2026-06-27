<?php
// VULN: SSRF -- fetches headers from a user-controlled URL via get_headers().
function check_url() {
    $u = $_GET['url'];
    $headers = get_headers($u);   // attacker points this at internal/metadata hosts
    return $headers;
}
