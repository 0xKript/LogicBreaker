void run_ping() {
    int count = atoi(getenv("COUNT"));
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "sleep %d", count);
    system(cmd);
}
