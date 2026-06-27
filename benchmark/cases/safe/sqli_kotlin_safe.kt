fun search() {
    val id = request.getParameter("id").toInt()
    val cursor = db.rawQuery("SELECT * FROM users WHERE id = " + id, null)
}
