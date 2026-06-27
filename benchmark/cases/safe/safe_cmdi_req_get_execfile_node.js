// SAFE: the header value is passed as a single argv element to execFile (no
// shell), so shell metacharacters are literal. Trap: a request header (req.get)
// reaches a process call (command-injection shape), but there is no shell.
const cp = require('child_process');
function listDir(req, res) {
    const name = req.get('X-Name');
    cp.execFile('/bin/ls', ['-l', name]);   // argv vector, no shell interpolation
    res.end('listed');
}
module.exports = listDir;
