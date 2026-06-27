void run_cmd() {
    int n = atoi(getenv("COUNT"));
    char buf[64];
    mysql_query(conn, "SELECT * FROM t WHERE n = " + n);
}
