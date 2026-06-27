// VULN: server Node reflects req.query into the HTML response (reflected XSS).
const express = require("express");
const app = express();
app.get("/search", (req, res) => {
  res.send("<div>Results for: " + req.query.q + "</div>");
});
app.listen(3000);
