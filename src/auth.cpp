#include "auth.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <cctype>
#include <memory>
#include <cstdio>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {

constexpr int kPbkdf2Iterations = 100000;
constexpr int kSaltBytes = 16;
constexpr int kHashBytes = 32;

std::string to_hex(const unsigned char* data, std::size_t n) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0x0F]);
    }
    return out;
}

bool from_hex(const std::string& hex, std::vector<unsigned char>& out) {
    if (hex.size() % 2) return false;
    out.clear();
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = nib(hex[i]), lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return true;
}

std::string random_token() {
    unsigned char buf[32];
    if (RAND_bytes(buf, sizeof buf) != 1) throw std::runtime_error("RAND_bytes failed");
    return to_hex(buf, sizeof buf);
}

std::string sha256_hex(const std::string& s) {
    unsigned char d[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(s.data()), s.size(), d);
    return to_hex(d, sizeof d);
}

// Format: pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
std::string hash_password(const std::string& password) {
    unsigned char salt[kSaltBytes];
    if (RAND_bytes(salt, sizeof salt) != 1) throw std::runtime_error("RAND_bytes failed");
    unsigned char out[kHashBytes];
    PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()), salt, sizeof salt,
                      kPbkdf2Iterations, EVP_sha256(), sizeof out, out);
    return "pbkdf2_sha256$" + std::to_string(kPbkdf2Iterations) + "$" +
           to_hex(salt, sizeof salt) + "$" + to_hex(out, sizeof out);
}

bool verify_password(const std::string& password, const std::string& stored) {
    // Split "pbkdf2_sha256$iter$salt$hash"
    std::vector<std::string> parts;
    std::size_t start = 0;
    for (std::size_t i = 0; i <= stored.size(); ++i) {
        if (i == stored.size() || stored[i] == '$') {
            parts.push_back(stored.substr(start, i - start));
            start = i + 1;
        }
    }
    if (parts.size() != 4 || parts[0] != "pbkdf2_sha256") return false;
    int iterations = 0;
    try { iterations = std::stoi(parts[1]); } catch (...) { return false; }
    std::vector<unsigned char> salt, expected;
    if (!from_hex(parts[2], salt) || !from_hex(parts[3], expected) || expected.empty()) return false;

    std::vector<unsigned char> actual(expected.size());
    PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()), salt.data(),
                      static_cast<int>(salt.size()), iterations, EVP_sha256(),
                      static_cast<int>(actual.size()), actual.data());
    return CRYPTO_memcmp(actual.data(), expected.data(), expected.size()) == 0;
}

// Used when the username does not exist, so login timing does not reveal accounts.
const std::string& dummy_hash() {
    static const std::string h = hash_password("not-a-real-password");
    return h;
}

}  // namespace


// ------------------------------------------------------------------ RateLimiter

bool RateLimiter::over(const std::string& key, int limit, int window_sec) {
    auto it = m_.find(key);
    if (it == m_.end()) return false;
    if (std::chrono::steady_clock::now() - it->second.start > std::chrono::seconds(window_sec)) {
        m_.erase(it);
        return false;
    }
    return it->second.count >= limit;
}

void RateLimiter::hit(const std::string& key, int window_sec) {
    auto now = std::chrono::steady_clock::now();
    auto it = m_.find(key);
    if (it == m_.end() || now - it->second.start > std::chrono::seconds(window_sec)) {
        if (m_.size() >= max_keys_) {
            for (auto i = m_.begin(); i != m_.end();)   // drop expired first, then everything
                i = (now - i->second.start > std::chrono::seconds(window_sec)) ? m_.erase(i) : std::next(i);
            if (m_.size() >= max_keys_) m_.clear();
        }
        m_[key] = E{1, now};
    } else {
        it->second.count++;
    }
}

// ------------------------------------------------------------------ Auth

Auth::Auth(Db& db, const Config& cfg, Worker& worker) : db_(db), cfg_(cfg), worker_(worker) {}

Auth::Result Auth::fail(int status, const std::string& msg) {
    Result r;
    r.http_status = status;
    r.error = msg;
    return r;
}

std::string Auth::normalize_username(const std::string& raw) {
    std::string out;
    for (char c : raw) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return out;
}

bool Auth::valid_username(const std::string& u) {
    if (u.size() < 3 || u.size() > 32) return false;
    for (char c : u) {
        bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
        if (!ok) return false;
    }
    return true;
}

bool Auth::valid_password(const std::string& p) {
    return p.size() >= 8 && p.size() <= 128;
}

static const char* kBusy = "Сервер занят, попробуйте через несколько секунд";
static const char* kServerErr = "Ошибка сервера, попробуйте ещё раз";

void Auth::register_user(const std::string& raw_username, const std::string& password,
                         const std::string& ip, ResultCb cb) {
    std::string username = normalize_username(raw_username);
    if (!valid_username(username))
        return cb(fail(400, "Имя пользователя: 3–32 символа, только латинские буквы, цифры и _"));
    if (!valid_password(password))
        return cb(fail(400, "Пароль должен быть от 8 до 128 символов"));

    const std::string rl_key = "reg|" + ip;
    if (limits_.over(rl_key, cfg_.register_per_ip_per_hour, 3600))
        return cb(fail(429, "Слишком много регистраций с вашего адреса. Попробуйте позже"));
    limits_.hit(rl_key, 3600);

    Db* db = &db_;
    const int days = cfg_.session_days, max_users = cfg_.max_users;
    auto cbp = std::make_shared<ResultCb>(std::move(cb));
    bool queued = worker_.submit<Result>(
        [db, username, password, days, max_users]() -> Result {
            try {
                std::string hash = hash_password(password);
                std::string token = random_token();
                // One round trip: create the user (unless the name is taken or the
                // account cap is reached) and its first session in the same statement.
                auto res = db->query(
                    "WITH u AS (INSERT INTO users (username, password_hash) "
                    "  SELECT $1, $2 WHERE (SELECT count(*) FROM users) < $3::int "
                    "  ON CONFLICT (username) DO NOTHING RETURNING id) "
                    "INSERT INTO sessions (token_hash, user_id, expires_at) "
                    "  SELECT $4, id, now() + make_interval(days => $5::int) FROM u RETURNING user_id",
                    {username, hash, std::to_string(max_users), sha256_hex(token), std::to_string(days)});
                if (PQntuples(res.get()) == 1) {
                    Result r;
                    r.ok = true; r.http_status = 200; r.token = token; r.username = username;
                    return r;
                }
                auto cnt = db->query("SELECT count(*)::bigint FROM users", {});
                if (std::stoll(PQgetvalue(cnt.get(), 0, 0)) >= max_users)
                    return fail(403, "Регистрация временно закрыта: достигнут лимит пользователей");
                return fail(409, "Такое имя уже занято");
            } catch (const std::exception& e) {
                std::cerr << "register error: " << e.what() << "\n";
                return fail(503, kServerErr);
            }
        },
        [cbp](Result r) { (*cbp)(std::move(r)); });
    if (!queued) (*cbp)(fail(503, kBusy));
}

void Auth::login(const std::string& raw_username, const std::string& password,
                 const std::string& ip, ResultCb cb) {
    std::string username = normalize_username(raw_username);
    if (!valid_username(username) || password.empty() || password.size() > 128)
        return cb(fail(401, "Неверное имя пользователя или пароль"));

    // Three independent counters: one guessed account cannot be hammered from many
    // addresses, and one address cannot walk through many accounts.
    const int w = cfg_.login_window_sec;
    const std::string k_ui = "ui|" + ip + "|" + username, k_u = "u|" + username, k_i = "i|" + ip;
    if (limits_.over(k_ui, cfg_.login_failures_per_user_ip, w) ||
        limits_.over(k_u, cfg_.login_failures_per_user, w) ||
        limits_.over(k_i, cfg_.login_failures_per_ip, w))
        return cb(fail(429, "Слишком много попыток. Подождите 15 минут"));

    Db* db = &db_;
    const int days = cfg_.session_days;
    auto cbp = std::make_shared<ResultCb>(std::move(cb));
    // The verdict comes back with a flag telling us whether to count a failure
    // (database errors are not the user's fault).
    struct Out { Result r; bool bad_credentials = false; };
    auto outp = [this, cbp, k_ui, k_u, k_i, w](Out o) {
        if (o.bad_credentials) { limits_.hit(k_ui, w); limits_.hit(k_u, w); limits_.hit(k_i, w); }
        else if (o.r.ok) limits_.clear(k_ui);
        (*cbp)(std::move(o.r));
    };
    bool queued = worker_.submit<Out>(
        [db, username, password, days]() -> Out {
            Out o;
            try {
                auto res = db->query("SELECT id, password_hash FROM users WHERE username = $1", {username});
                bool found = PQntuples(res.get()) == 1;
                std::string stored = found ? PQgetvalue(res.get(), 0, 1) : dummy_hash();
                bool good = verify_password(password, stored) && found;   // same work either way
                if (!good) {
                    o.r = fail(401, "Неверное имя пользователя или пароль");
                    o.bad_credentials = true;
                    return o;
                }
                std::string token = random_token();
                db->query("INSERT INTO sessions (token_hash, user_id, expires_at) "
                          "VALUES ($1, $2, now() + make_interval(days => $3::int))",
                          {sha256_hex(token), PQgetvalue(res.get(), 0, 0), std::to_string(days)});
                o.r.ok = true; o.r.http_status = 200; o.r.token = token; o.r.username = username;
            } catch (const std::exception& e) {
                std::cerr << "login error: " << e.what() << "\n";
                o.r = fail(503, kServerErr);
            }
            return o;
        },
        outp);
    if (!queued) (*cbp)(fail(503, kBusy));
}

void Auth::logout(const std::string& token) {
    if (token.size() != 64) return;
    std::string h = sha256_hex(token);
    cache_.erase(h);
    Db* db = &db_;
    worker_.submit_void([db, h]() {
        try { db->query("DELETE FROM sessions WHERE token_hash = $1", {h}); }
        catch (const std::exception& e) { std::cerr << "logout error: " << e.what() << "\n"; }
    });
}

void Auth::validate(const std::string& token, ValidateCb cb) {
    // Cheap rejects first: anonymous visitors and garbage cookies never reach the database.
    bool hex = token.size() == 64;
    for (char c : token) if (!std::isxdigit(static_cast<unsigned char>(c))) { hex = false; break; }
    if (!hex) return cb(Validation{});

    std::string h = sha256_hex(token);
    auto now = std::chrono::steady_clock::now();
    auto it = cache_.find(h);
    if (it != cache_.end()) {
        if (now < it->second.expires) return cb(Validation{it->second.username, false});
        cache_.erase(it);
    }

    Db* db = &db_;
    auto cbp = std::make_shared<ValidateCb>(std::move(cb));
    bool queued = worker_.submit<Validation>(
        [db, h]() -> Validation {
            Validation v;
            try {
                auto res = db->query(
                    "SELECT u.username FROM sessions s JOIN users u ON u.id = s.user_id "
                    "WHERE s.token_hash = $1 AND s.expires_at > now()", {h});
                if (PQntuples(res.get()) == 1) v.user = std::string(PQgetvalue(res.get(), 0, 0));
            } catch (const std::exception& e) {
                std::cerr << "validate error: " << e.what() << "\n";
                v.busy = true;   // database trouble: report 503 instead of logging the user out
            }
            return v;
        },
        [this, cbp, h](Validation v) {
            if (v.user) {
                if (cache_.size() >= 4096) cache_.clear();
                cache_[h] = Cached{*v.user, std::chrono::steady_clock::now() + std::chrono::seconds(60)};
            }
            (*cbp)(std::move(v));
        });
    if (!queued) { Validation v; v.busy = true; (*cbp)(std::move(v)); }
}

void Auth::cleanup_expired() {
    Db* db = &db_;
    worker_.submit_void([db]() {
        try { db->query("DELETE FROM sessions WHERE expires_at < now()", {}); }
        catch (const std::exception& e) { std::cerr << "cleanup error: " << e.what() << "\n"; }
    });
    auto now = std::chrono::steady_clock::now();
    for (auto it = cache_.begin(); it != cache_.end();)
        it = (now >= it->second.expires) ? cache_.erase(it) : std::next(it);
}
