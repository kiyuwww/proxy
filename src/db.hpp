#pragma once
#include <libpq-fe.h>

#include <memory>
#include <string>
#include <vector>

// RAII owner for a libpq result.
using PgResult = std::unique_ptr<PGresult, decltype(&PQclear)>;

// Minimal PostgreSQL wrapper: one connection, reconnects when it drops.
// All queries are parameterized ($1, $2, ...), never built by string concatenation.
// Used from exactly one thread at a time (migration at startup, then the worker thread).
class Db {
public:
    explicit Db(std::string url);
    ~Db();
    Db(const Db&) = delete;
    Db& operator=(const Db&) = delete;

    // Opens the connection and creates tables if needed. Throws on failure.
    void connect_and_migrate();

    // Parameterized query. Reconnects and retries once if the connection was lost.
    // Throws std::runtime_error on SQL error (message does not contain the URL).
    PgResult query(const std::string& sql, const std::vector<std::string>& params);

    // Multi-statement script without parameters (used for migrations).
    void exec_script(const std::string& sql);

private:
    void ensure_connected();
    void drop_connection();

    std::string url_;
    PGconn* conn_ = nullptr;
    bool migrated_ = false;
};
