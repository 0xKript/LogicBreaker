<?php
// SAFE: the username is neutralised with ldap_escape() before being placed in
// the filter. Trap: the string concatenation into "(uid=...)" looks like LDAP
// injection, but the escaping makes metacharacters inert.
function ldap_login($conn) {
    $user = ldap_escape($_POST['user'], '', LDAP_ESCAPE_FILTER);
    $filter = "(uid=" . $user . ")";
    return ldap_search($conn, "dc=corp,dc=com", $filter);
}
