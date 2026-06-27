<?php
// VULN: PDO query built by concatenating $_GET (no bound parameter).
function search(PDO $pdo) {
    $term = $_GET['term'];
    $stmt = $pdo->query("SELECT * FROM products WHERE name LIKE '%" . $term . "%'");
    return $stmt->fetchAll();
}
