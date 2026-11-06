#pragma once
#include <chrono>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include "config.hpp"
#include "db.hpp"
#include "worker.hpp"

// Fixed-window counters keyed by string (in memory, bounded, reset on restart).
class RateLimiter {
public:
    explicit RateLimiter(std::size_t max_keys = 20000) : max_keys_(max_keys) {}
    bool over(const std::string& key, int limit, int window_sec);
    void hit(const std::string& key, int window_sec);
    void clear(const std::string& key) { m_.erase(key); }

private:
    struct E { int count; std::chrono::steady_clock::time_point start; };
    std::size_t max_keys_;
    std::unordered_map<std::string, E> m_;
};

// Username + password accounts with server-side sessions stored in PostgreSQL.
// - Passwords: PBKDF2-HMAC-SHA256 with a random salt per user.
// - Session tokens: 256-bit random values; only their SHA-256 is stored.
// - All database work and hashing runs on the Worker thread; callbacks run on the
//   network thread. Throttle state and the session cache are touched only there.
class Auth {
public:
    Auth(Db& db, const Config& cfg, Worker& worker);

    struct Result {
        bool ok = false;
        std::string error;     // human-readable (Russian), safe to show to the user
        int http_status = 400;
        std::string token;     // session token, set on success
        std::string username;  // normalized username, set on success
    };
    struct Validation {
        std::optional<std::string> user;
        bool busy = false;     // worker queue full: answer 503, not 401
    };
    using ResultCb = std::function<void(Result)>;
    using ValidateCb = std::function<void(Validation)>;

    void register_user(const std::string& username, const std::string& password,
                       const std::string& ip, ResultCb cb);
    void login(const std::string& username, const std::string& password,
               const std::string& ip, ResultCb cb);
    void logout(const std::string& token);
    // Calls cb synchronously on a cache hit or an obviously invalid token.
    void validate(const std::string& token, ValidateCb cb);
    // Deletes expired sessions (call occasionally).
    void cleanup_expired();

    static std::string normalize_username(const std::string& raw);
    static bool valid_username(const std::string& u);
    static bool valid_password(const std::string& p);

private:
    static Result fail(int status, const std::string& msg);

    Db& db_;
    const Config& cfg_;
    Worker& worker_;
    RateLimiter limits_;
    struct Cached { std::string username; std::chrono::steady_clock::time_point expires; };
    std::unordered_map<std::string, Cached> cache_;   // sha256(token) -> user, 60 s
};
