// VULN: path traversal -- deletes a file at a user-controlled path (fs.unlinkSync).
const fs = require('fs');
function removeUpload(req, res) {
    const name = req.query.name;
    fs.unlinkSync('/var/uploads/' + name);   // ../../etc -> deletes outside uploads
    res.end('ok');
}
module.exports = removeUpload;
