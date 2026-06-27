<?php
// VULN: SQL injection in PHP
function findUser($conn, $username) {
    $sql = "SELECT * FROM users WHERE username = '" . $username . "'";
    return $conn->query($sql);
}
