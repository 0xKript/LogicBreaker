// VULN: server-side Node. User input flows into child_process.exec (real shell).
const express = require("express");
const { exec } = require("child_process");
const app = express();
app.get("/ping", (req, res) => {
  const host = req.query.host;
  exec("ping -c 1 " + host, (err, stdout) => {   // command injection
    res.send(stdout);
  });
});
app.listen(3000);
