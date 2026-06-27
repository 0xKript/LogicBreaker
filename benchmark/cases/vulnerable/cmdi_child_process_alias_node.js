// VULN: command injection via aliased child_process.exec (CWE-78).
const cp = require('child_process');
function ping(req, res) {
    cp.exec("ping " + req.query.host);
}
