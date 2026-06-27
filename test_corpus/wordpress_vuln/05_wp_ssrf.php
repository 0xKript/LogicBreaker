<?php
/**
 * Vuln WP 05: SSRF via file_get_contents with user URL.
 */
class Preview_Plugin {

    public function fetch_preview() {
        $url = $_GET['url'];
        $content = file_get_contents($url);
        echo $content;
    }
}
