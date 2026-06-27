<?php
/**
 * Adversarial safe WP: file read with realpath + containment check.
 */
class File_Plugin {

    public function read() {
        $name = $_GET['name'];
        $base = plugin_dir_path(__FILE__) . 'data/';
        $path = realpath($base . basename($name));
        // containment check: resolved path must stay under $base
        if ($path === false || strpos($path, $base) !== 0) {
            wp_die('invalid', 400);
        }
        return file_get_contents($path);
    }
}
