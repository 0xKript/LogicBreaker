<?php
// VULN: XPath expression concatenates raw request input.
function find_user(DOMXPath $xp) {
    $name = $_GET['name'];
    $nodes = $xp->query("/users/user[name='" . $name . "']/role");
    return $nodes->item(0)->nodeValue;
}
