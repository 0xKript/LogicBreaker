<?php
// SAFE: is_admin() is a "are we on an admin page" predicate, and the $_GET value
// is an unrelated feature flag -- not a client-supplied role used for authz.
function use_block_editor($post) {
    if ( is_admin() && isset($_GET['meta-box-loader']) ) {
        check_admin_referer('meta-box-loader', 'meta-box-loader-nonce');
        return false;
    }
    return true;
}
