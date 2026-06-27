// SAFE: RegExp.prototype.exec, not child_process -- no command execution.
function parseId(req) {
    const re = /(\d+)/;
    return re.exec("id=" + req.query.id);
}
