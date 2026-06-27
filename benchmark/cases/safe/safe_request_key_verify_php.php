<?php
// SAFE: the request id is integer-cast and a secret confirmation key is verified
// with the password hasher, so possessing the right key IS the authorization.
function validate_request_key($request_id, $key) {
    global $wp_hasher;
    $request_id = absint($request_id);
    $request    = get_user_request($request_id);
    if ( ! $request ) {
        return false;
    }
    if ( ! $wp_hasher->CheckPassword($key, $request->confirm_key) ) {
        return new WP_Error('invalid_key', 'Invalid key');
    }
    return $request;
}
