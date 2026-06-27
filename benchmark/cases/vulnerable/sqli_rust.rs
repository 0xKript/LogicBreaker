fn search(req: HttpRequest) {
    let u = req.query_string();
    let rows = conn.execute(&format!("SELECT * FROM users WHERE name = '{}'", u));
}
