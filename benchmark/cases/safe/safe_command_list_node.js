// SAFE: execFile with an argv array and no shell. Trap: a user value reaches a
// child-process call (command-injection shape), but execFile passes it as a
// single argument; there is no shell to interpret metacharacters.
const express = require("express");
const { execFile } = require("child_process");
const app = express();
app.get("/ping", (req, res) => {
  execFile("ping", ["-c", "1", req.query.host], (e, out) => res.send(out));
});
app.listen(3000);
