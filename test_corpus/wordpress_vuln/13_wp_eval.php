<?php
/**
 * Hidden WP: code injection via eval on user input.
 */
class Calculator_Plugin {

    public function calc() {
        $expr = $_POST['expr'];
        $result = eval('return ' . $expr . ';');
        wp_send_json_success($result);
    }
}
