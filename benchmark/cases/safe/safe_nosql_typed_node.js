// SAFE: server Node + Mongo. Trap: req.body flows into findOne(), which looks
// like NoSQL operator injection, but each value is coerced with String(), so an
// attacker cannot smuggle a {$ne:...} object -- only a plain string is queried.
const express = require("express");
const { MongoClient } = require("mongodb");
const app = express();
app.use(express.json());
app.post("/login", async (req, res) => {
  const db = (await MongoClient.connect("mongodb://localhost")).db("app");
  const user = await db.collection("users").findOne({
    username: String(req.body.username),
    password: String(req.body.password),
  });
  res.json({ ok: !!user });
});
