void run_ping() {
    std::string host = getenv("HOST");
    std::string cmd = "ping -c 1 " + host;
    system(cmd.c_str());
}
