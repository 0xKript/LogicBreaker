// SAFE: the value is wrapped in an explicit $eq, forcing an equality match.
// Trap: req.body flows into findOne() (NoSQL-injection shape), but $eq prevents
// an attacker from supplying their own operator object like {$ne:null}.
const express = require("express");
const { MongoClient } = require("mongodb");
const app = express();
app.use(express.json());
app.post("/find", async (req, res) => {
  const db = (await MongoClient.connect("mongodb://localhost")).db("app");
  const u = await db.collection("users").findOne({ username: { $eq: req.body.username } });
  res.json({ ok: !!u });
});
