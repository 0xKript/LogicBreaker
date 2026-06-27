// VULN: OS command injection -- a request header (req.get) is concatenated into
// a shell command run via execSync.
const cp = require('child_process');
function ping(req, res) {
    const host = req.get('X-Target');
    cp.execSync('ping -c1 ' + host);   // header carries `; rm -rf /`
    res.end('pinged');
}
module.exports = ping;
