<?php
// VULN: LDAP filter built from raw user input (auth bypass via *).
function ldap_login($conn) {
    $user = $_POST['user'];
    $filter = "(uid=" . $user . ")";
    $search = ldap_search($conn, "dc=corp,dc=com", $filter);
    return ldap_get_entries($conn, $search);
}
