<?php
// VULN (plugin-style): a live API secret committed in the plugin source.
$myplugin_api_secret = 'TESTKEY_9aXcVbNm2hJ4Kd6Ys1pQrStUvWxYz012345';
function myplugin_call_api($payload) {
    global $myplugin_api_secret;
    return wp_remote_post('https://api.vendor.com/v1/push', array(
        'headers' => array('Authorization' => 'Bearer ' . $myplugin_api_secret),
        'body'    => $payload,
    ));
}
