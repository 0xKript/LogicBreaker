fun search() {
    val name = request.getParameter("name")
    val cursor = db.rawQuery("SELECT * FROM users WHERE name = '" + name + "'", null)
}
