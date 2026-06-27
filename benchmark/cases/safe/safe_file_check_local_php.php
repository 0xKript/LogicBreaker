<?php
// SAFE: an HTTP client reading its OWN fixed local files to build an upload.
// The path is not attacker-influenced, so the check-then-open is not a TOCTOU.
function prepare_body($files) {
    $out = '';
    foreach ($files as $file) {
        if ( is_readable($file) ) {
            $fp = fopen($file, 'r');
            $out .= fread($fp, filesize($file));
            fclose($fp);
        }
    }
    return $out;
}
