public class UserController {
    public void Search() {
        int id = int.Parse(Request.Query["id"]);
        var cmd = new SqlCommand("SELECT * FROM Users WHERE id = " + id);
        cmd.ExecuteReader();
    }
}
