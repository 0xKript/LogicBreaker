// VULN: Java Runtime.exec with a request-derived argument (command injection).
public class PingServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String host = req.getParameter("host");
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }
}
