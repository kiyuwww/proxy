#include "db.hpp"

#include <stdexcept>

namespace {

constexpr const char* kSchema = R"SQL(
SET client_min_messages = warning;
-- One migration at a time: concurrent instances (e.g. during a redeploy) wait here.
BEGIN;
SELECT pg_advisory_xact_lock(727274);
CREATE TABLE IF NOT EXISTS users (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE CHECK (username ~ '^[a-z0-9_]{3,32}$'),
    password_hash TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);
CREATE INDEX IF NOT EXISTS sessions_expires_idx ON sessions(expires_at);
-- Supabase exposes public tables through its REST API. Enabling RLS with no
-- policies means anon/public API keys cannot read or write these tables; this
-- server connects as the table owner, which bypasses RLS.
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
COMMIT;
)SQL";

}  // namespace

Db::Db(std::string url) : url_(std::move(url)) {}

Db::~Db() {
    if (conn_) PQfinish(conn_);
}

void Db::drop_connection() {
    if (conn_) { PQfinish(conn_); conn_ = nullptr; }
}

void Db::ensure_connected() {
    if (conn_ && PQstatus(conn_) == CONNECTION_OK) return;
    drop_connection();
    // Timeouts and TCP keepalives matter on free tiers: poolers silently drop idle
    // connections, and a dead peer must never hang the worker thread for minutes.
    const char* keys[] = {"dbname", "connect_timeout", "keepalives", "keepalives_idle",
                          "keepalives_interval", "keepalives_count", "application_name", nullptr};
    const char* vals[] = {url_.c_str(), "10", "1", "30", "10", "3", "scramjet-cpp", nullptr};
    conn_ = PQconnectdbParams(keys, vals, 1);
    if (!conn_ || PQstatus(conn_) != CONNECTION_OK) {
        std::string err = conn_ ? PQerrorMessage(conn_) : "out of memory";
        drop_connection();
        throw std::runtime_error("database connection failed: " + err);
    }
    // Create the tables on first use. Doing it here (not only at boot) means a database
    // that was unreachable at startup, or is paused on a free tier, heals itself.
    if (!migrated_) {
        PgResult res(PQexec(conn_, kSchema), &PQclear);
        if (!res || (PQresultStatus(res.get()) != PGRES_COMMAND_OK && PQresultStatus(res.get()) != PGRES_TUPLES_OK)) {
            std::string err = res ? PQresultErrorMessage(res.get()) : "no result";
            drop_connection();
            throw std::runtime_error("migration failed: " + err);
        }
        migrated_ = true;
    }
}

void Db::connect_and_migrate() {
    ensure_connected();   // connects and migrates (once)
}

void Db::exec_script(const std::string& sql) {
    ensure_connected();
    PgResult res(PQexec(conn_, sql.c_str()), &PQclear);
    if (!res || (PQresultStatus(res.get()) != PGRES_COMMAND_OK && PQresultStatus(res.get()) != PGRES_TUPLES_OK))
        throw std::runtime_error(std::string("migration failed: ") + (res ? PQresultErrorMessage(res.get()) : "no result"));
}

PgResult Db::query(const std::string& sql, const std::vector<std::string>& params) {
    std::vector<const char*> values;
    values.reserve(params.size());
    for (const auto& p : params) values.push_back(p.c_str());

    // One retry: a pooled connection that was closed while idle only shows up on use.
    for (int attempt = 0; attempt < 2; ++attempt) {
        ensure_connected();
        PgResult res(PQexecParams(conn_, sql.c_str(), static_cast<int>(params.size()),
                                  nullptr, values.data(), nullptr, nullptr, 0), &PQclear);
        if (!res) { drop_connection(); if (attempt == 0) continue; throw std::runtime_error("query failed: no result"); }
        auto status = PQresultStatus(res.get());
        if (status == PGRES_TUPLES_OK || status == PGRES_COMMAND_OK) return res;
        if (PQstatus(conn_) != CONNECTION_OK) {   // transport failure, not a SQL error
            drop_connection();
            if (attempt == 0) continue;
        }
        throw std::runtime_error(std::string("query failed: ") + PQresultErrorMessage(res.get()));
    }
    throw std::runtime_error("query failed");
}
