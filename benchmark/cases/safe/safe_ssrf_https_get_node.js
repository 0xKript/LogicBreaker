// SAFE: the requested host is checked against a fixed allow-list, then the
// request goes to a CONSTANT URL. Trap: reads req.query and calls https.get
// (SSRF shape), but no user-controlled value reaches the request.
const https = require('https');
const ALLOWED = ['api.example.com', 'cdn.example.com'];
function fetchStatus(req, res) {
    const host = new URL(req.query.url).hostname;
    if (!ALLOWED.includes(host)) { res.end('blocked'); return; }
    https.get('https://api.example.com/status', (r) => { r.pipe(res); });
}
module.exports = fetchStatus;
