// SAFE: PreparedStatement with a bound parameter. Trap: the SQL string plus a
// user value nearby looks like concatenation, but setString binds the value.
public class UserDao {
    public User find(java.sql.Connection con, String email) throws Exception {
        PreparedStatement ps = con.prepareStatement("SELECT id FROM users WHERE email = ?");
        ps.setString(1, email);
        return map(ps.executeQuery());
    }
}
