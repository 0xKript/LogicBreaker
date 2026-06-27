<?php
/**
 * Safe WP 02: XSS prevented via esc_html.
 */
class Comment_Plugin {

    public function show() {
        $user_input = $_POST['comment'];
        echo "<div class='comment'>" . esc_html($user_input) . "</div>";
        wp_die();
    }
}
