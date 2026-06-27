<?php
/**
 * Vuln WP 03: Path Traversal via include with user input.
 */
class Template_Loader {

    public function render_template() {
        $tpl = $_GET['template'];
        $path = plugin_dir_path(__FILE__) . 'templates/' . $tpl . '.php';
        include($path);
    }
}
