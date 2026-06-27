<?php
/**
 * Safe WP 05: password hashing via wp_hash_password (bcrypt).
 */
class Auth_Plugin {

    public function hash_password($pw) {
        return wp_hash_password($pw);
    }

    public function verify_password($pw, $stored) {
        return wp_check_password($pw, $stored);
    }
}
