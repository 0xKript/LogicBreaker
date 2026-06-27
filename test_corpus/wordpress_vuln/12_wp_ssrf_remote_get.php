<?php
/**
 * Hidden WP: SSRF via wp_remote_get with user-controlled URL.
 */
class Fetcher_Plugin {

    public function fetch_url() {
        $url = $_GET['url'];
        $resp = wp_remote_get($url);
        if (is_wp_error($resp)) {
            return '';
        }
        return wp_remote_retrieve_body($resp);
    }
}
