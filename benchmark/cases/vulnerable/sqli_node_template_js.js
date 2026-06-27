// VULN: server Node, mysql query built with a template literal from req input.
const mysql = require("mysql2");
const express = require("express");
const app = express();
const db = mysql.createConnection({ host: "localhost" });
app.get("/u", (req, res) => {
  const id = req.query.id;
  db.query(`SELECT * FROM users WHERE id = ${id}`, (e, rows) => res.json(rows));
});
app.listen(3000);
