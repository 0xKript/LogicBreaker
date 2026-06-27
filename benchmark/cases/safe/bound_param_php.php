<?php
function handle() {
    $u = $_GET["name"];
    $stmt = $pdo->prepare("SELECT * FROM users WHERE name = ?");
    $stmt->execute([$u]);
}
