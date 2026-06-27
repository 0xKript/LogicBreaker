public class UserController {
    public void Search() {
        string u = Request.Query["name"];
        var cmd = new SqlCommand("SELECT * FROM Users WHERE name = '" + u + "'");
        cmd.ExecuteReader();
    }
}
