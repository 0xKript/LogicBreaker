<?php
// SAFE: loadHTML parses HTML (no XML DTD / external entities), and entity
// loading is disabled for older PHP anyway.
function parse_feed_html($data) {
    if ( function_exists('libxml_disable_entity_loader') && PHP_VERSION_ID < 80000 ) {
        libxml_disable_entity_loader(true);
    }
    $doc = new DOMDocument();
    @$doc->loadHTML($data);
    return $doc;
}
