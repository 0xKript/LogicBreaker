<?php
/**
 * Vuln WP 08: Insecure deserialization via unserialize().
 */
class Import_Plugin {

    public function import_settings() {
        $data = $_POST['settings'];
        $obj = unserialize($data);
        update_option('my_settings', $obj);
    }
}
