<?php
// SAFE: PDO named placeholder bound via execute(). Trap: the ":email" in the SQL
// string looks like interpolation, but it is a bound parameter; the value is
// passed separately and never concatenated.
function find_user(PDO $pdo) {
    $stmt = $pdo->prepare("SELECT id FROM users WHERE email = :email");
    $stmt->execute([':email' => $_GET['email']]);
    return $stmt->fetch();
}
