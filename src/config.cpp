#include "config.hpp"

#include <cstdlib>
#include <fstream>
#include <sstream>

namespace {

// Minimal .env loader: KEY=VALUE per line, '#' comments, optional quotes.
// Real environment variables always win over the file.
void load_dotenv(const char* path) {
    std::ifstream in(path);
    if (!in) return;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);
        while (!key.empty() && (key.back() == ' ' || key.back() == '\r')) key.pop_back();
        while (!val.empty() && (val.back() == '\r' || val.back() == ' ')) val.pop_back();
        if (val.size() >= 2 && (val.front() == '"' || val.front() == '\'') && val.back() == val.front())
            val = val.substr(1, val.size() - 2);
        if (!key.empty() && std::getenv(key.c_str()) == nullptr)
            setenv(key.c_str(), val.c_str(), 0);
    }
}

std::string env_str(const char* name, const std::string& def) {
    const char* v = std::getenv(name);
    return (v && *v) ? std::string(v) : def;
}

bool env_bool(const char* name, bool def) {
    const char* v = std::getenv(name);
    if (!v || !*v) return def;
    std::string s(v);
    return s == "1" || s == "true" || s == "yes" || s == "on";
}

long env_long(const char* name, long def) {
    const char* v = std::getenv(name);
    if (!v || !*v) return def;
    try { return std::stol(v); } catch (...) { return def; }
}

}  // namespace

Config load_config() {
    load_dotenv(".env");

    Config c;
    c.host = env_str("HOST", c.host);
    c.port = static_cast<std::uint16_t>(env_long("PORT", 8080));
    c.public_dir = env_str("PUBLIC_DIR", c.public_dir);
    c.static_dir = env_str("STATIC_DIR", c.static_dir);
    c.supabase_url = env_str("SUPABASE_URL", "");
    c.supabase_anon_key = env_str("SUPABASE_ANON_KEY", "");
    c.allow_private_ips = env_bool("ALLOW_PRIVATE_IPS", false);
    c.allow_loopback_ips = env_bool("ALLOW_LOOPBACK_IPS", false);

    std::string bl = env_str("HOSTNAME_BLACKLIST", "");
    if (!bl.empty()) {
        c.hostname_blacklist_regex.clear();
        std::stringstream ss(bl);
        std::string item;
        while (std::getline(ss, item, ',')) if (!item.empty()) c.hostname_blacklist_regex.push_back(item);
    }
    c.max_streams_per_session = static_cast<std::size_t>(env_long("MAX_STREAMS", 256));
    return c;
}
