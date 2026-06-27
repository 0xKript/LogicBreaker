<?php
// SAFE: the host param must be on a fixed allow-list, after which the request is
// made to a CONSTANT, server-controlled URL. Trap: reads $_GET and calls
// get_headers (SSRF shape), but no user data reaches the request.
function check_status() {
    $host = $_GET['host'];
    $allowed = ['api.example.com', 'cdn.example.com'];
    if (!in_array($host, $allowed)) { die("blocked"); }
    return get_headers("https://api.example.com/health");
}
