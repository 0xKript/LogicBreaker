// SAFE: mysql2 "?" placeholder with a values array. Trap: req.query.id is passed
// to .query(), which looks like injection, but it is bound, not concatenated.
const express = require("express");
const mysql = require("mysql2");
const app = express();
const db = mysql.createConnection({ host: "localhost" });
app.get("/u", (req, res) => {
  db.query("SELECT * FROM users WHERE id = ?", [req.query.id], (e, rows) => res.json(rows));
});
app.listen(3000);
