function runQuery(q) {
    db.query(q);
}
function dispatch(x) {
    runQuery(x);
}
app.get("/search", (req, res) => {
    const u = req.query.name;
    dispatch("SELECT * FROM users WHERE name = '" + u + "'");
});
