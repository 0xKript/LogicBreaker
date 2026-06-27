app.get("/search", (req, res) => {
    const name = req.query.name;
    db.query("SELECT * FROM users WHERE name = ?", [name]);
});
