// VULN: Mongo query takes the raw request body, allowing operator injection.
const express = require("express");
const { MongoClient } = require("mongodb");
const app = express();
app.use(express.json());
app.post("/login", async (req, res) => {
  const db = (await MongoClient.connect("mongodb://localhost")).db("app");
  const user = await db.collection("users").findOne({
    username: req.body.username,
    password: req.body.password,     // {"$ne": null} bypasses auth
  });
  res.json({ ok: !!user });
});
