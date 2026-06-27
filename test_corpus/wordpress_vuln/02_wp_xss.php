<?php
/**
 * Vuln WP 02: XSS via echo without escaping.
 */
class Comment_Plugin {

    public function __construct() {
        add_action('wp_ajax_show_comment', array($this, 'show'));
    }

    public function show() {
        $user_input = $_POST['comment'];
        echo "<div class='comment'>" . $user_input . "</div>";
        wp_die();
    }
}
