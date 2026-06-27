<?php
// VULN: reflects a request value into HTML with no escaping (reflected XSS).
function search_page() {
    $q = $_GET['q'];
    echo "<div class='result'>You searched for: " . $q . "</div>";
}
