<?php
/**
 * Vuln WP 07: MD5 used for password hashing.
 */
class Auth_Plugin {

    public function hash_password($pw) {
        return md5($pw);
    }

    public function verify_password($pw, $stored) {
        return md5($pw) === $stored;
    }
}
