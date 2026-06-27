<?php
// SAFE: the option name is bound via $wpdb->prepare() inside the helper, so the
// value reaching the query sink is parameterized (no interprocedural SQLi).
function read_option($name) {
    global $wpdb;
    return $wpdb->get_var(
        $wpdb->prepare("SELECT option_value FROM $wpdb->options WHERE option_name = %s", $name)
    );
}
function show_setting() {
    $key = $_GET['key'];
    return read_option($key);
}
