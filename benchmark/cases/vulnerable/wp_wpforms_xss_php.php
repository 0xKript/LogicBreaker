<?php
// VULN (WPForms-style): a submitted field is echoed into admin HTML unescaped.
add_action('wpforms_process_complete', 'show_submission');
function show_submission($fields) {
    echo "<div class='entry'>Name: " . $_POST['wpforms']['fields']['name'] . "</div>";
}
