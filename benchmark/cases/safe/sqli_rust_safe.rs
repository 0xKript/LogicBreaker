fn search(req: HttpRequest) {
    let id = req.query_string().parse::<i64>().unwrap();
    let rows = conn.execute(&format!("SELECT * FROM users WHERE id = {}", id));
}
