// VULN: server Node reads a file at a user-controlled path (path traversal).
const fs = require("fs");
const http = require("http");
const url = require("url");
http.createServer((req, res) => {
  const q = url.parse(req.url, true).query;
  fs.readFile("/var/data/" + q.file, (e, data) => res.end(data));  // ../ escapes root
}).listen(8080);
