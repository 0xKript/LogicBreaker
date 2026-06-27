<?php
/**
 * Hidden WP: SSTI via include with user-controlled template path.
 */
class Theme_Plugin {

    public function render() {
        $tpl = $_GET['template'];
        // include with user-controlled path = path traversal AND potential SSTI
        include(get_template_directory() . '/' . $tpl);
    }
}
