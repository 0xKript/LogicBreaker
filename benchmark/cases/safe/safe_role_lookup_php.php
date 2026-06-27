<?php
// SAFE: the client 'role' is only an array-lookup key to fetch a display label
// for an email; it never gates access or sets a privilege.
function created_user_email($text) {
    $roles = get_editable_roles();
    $role  = $roles[ $_REQUEST['role'] ];
    return str_replace('%role%', translate_user_role($role['name']), $text);
}
