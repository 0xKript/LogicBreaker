// SAFE: path.basename() strips directory components before the unlink, keeping
// the target inside the uploads directory. Trap: deletes a path built from
// req.query (path-traversal shape), but basename() neutralises `../`.
const fs = require('fs');
const path = require('path');
function removeUpload(req, res) {
    const name = path.basename(req.query.name);
    fs.unlinkSync('/var/uploads/' + name);
    res.end('ok');
}
module.exports = removeUpload;
