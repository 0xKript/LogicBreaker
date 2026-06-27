<?php
// SAFE: htmlspecialchars() encodes the value before echo. Trap: a $_GET value is
// echoed into HTML (reflected XSS shape), but the encoding makes it inert.
function render() {
    $q = htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8');
    echo "<div class='result'>You searched: " . $q . "</div>";
}
