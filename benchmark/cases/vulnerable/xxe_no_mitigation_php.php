<?php
// VULN: parses attacker XML with no entity-loader hardening (XXE).
function import_xml() {
    $data = file_get_contents('php://input');
    $xml = simplexml_load_string($data);
    return $xml->name;
}
