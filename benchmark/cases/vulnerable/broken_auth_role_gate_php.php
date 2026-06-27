<?php
// VULN: trusts a client-supplied role to grant admin access (CWE-602).
function admin_panel() {
    $role = $_POST['role'];
    if ( $role == 'admin' ) {
        grant_admin_access();
        return render_admin_dashboard();
    }
    return render_login();
}
