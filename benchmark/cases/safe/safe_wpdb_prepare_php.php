<?php
// SAFE: parameterized via $wpdb->prepare() with a %s placeholder.
function get_user_row($username) {
    global $wpdb;
    return $wpdb->get_row(
        $wpdb->prepare("SELECT ID, user_login FROM $wpdb->users WHERE user_login = %s LIMIT 1", $username)
    );
}
