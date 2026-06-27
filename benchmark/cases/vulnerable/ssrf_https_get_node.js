// VULN: SSRF -- fetches a user-controlled URL over https.get().
const https = require('https');
function fetchStatus(req, res) {
    const u = req.query.url;
    https.get(u, (r) => { r.pipe(res); });   // attacker controls the destination
}
module.exports = fetchStatus;
