void run_cmd() {
    char *user_cmd = getenv("USER_CMD");
    system(user_cmd);
}
