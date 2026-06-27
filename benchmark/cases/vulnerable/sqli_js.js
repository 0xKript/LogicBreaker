app.get("/search", function(req, res) {
    const q = req.query.q;
    // VULN: SQL injection via template literal
    db.query(`SELECT * FROM items WHERE title = '${q}'`);
    res.json([]);
});
