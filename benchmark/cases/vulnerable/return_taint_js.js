function getSearchTerm(req) {
    return req.query.q;
}
app.get("/search", (req, res) => {
    const term = getSearchTerm(req);
    db.query(term);
});
