<?php
// VULN (plugin-style): untrusted option blob passed to unserialize (object inj).
add_action('wp_ajax_load_rules', 'plugin_load_rules');
function plugin_load_rules() {
    $data = $_POST['rules'];
    $rules = unserialize($data);
    return $rules;
}
