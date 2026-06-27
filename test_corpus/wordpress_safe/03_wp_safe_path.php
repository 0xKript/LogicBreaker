<?php
/**
 * Safe WP 03: Path traversal prevented via validate_file + basename.
 */
class Template_Loader {

    public function render_template() {
        $tpl = basename($_GET['template']);
        if (validate_file($tpl) !== 0) {
            wp_die('invalid template', 400);
        }
        $path = plugin_dir_path(__FILE__) . 'templates/' . $tpl . '.php';
        include($path);
    }
}
