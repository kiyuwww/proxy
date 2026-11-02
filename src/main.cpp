// Scramjet demo server (C++ rewrite).
// Serves the web client and the Wisp websocket endpoint (/wisp/) that the
// browser's libcurl transport uses to reach the internet.
#include <csignal>
#include <iostream>
#include <sstream>

#include <boost/asio.hpp>

#include "config.hpp"
#include "http_server.hpp"
#include "net_policy.hpp"
#include "static_files.hpp"

namespace {

std::string json_string(const std::string& s) {
    std::string out = "\"";
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '<': out += "\\u003c"; break;  // keeps </script> inert if ever inlined
            default: out += c;
        }
    }
    return out + "\"";
}

// Generated at startup from environment variables, so no secrets live in the repo.
std::string app_config_js(const Config& cfg) {
    std::ostringstream js;
    js << "window.APP_CONFIG = {"
       << "supabaseUrl: " << json_string(cfg.supabase_url) << ", "
       << "supabaseAnonKey: " << json_string(cfg.supabase_anon_key)
       << "};\n";
    return js.str();
}

}  // namespace

int main() {
    std::signal(SIGPIPE, SIG_IGN);

    Config cfg = load_config();

    StaticFiles files;
    files.mount(cfg.public_dir, "/");
    files.mount(cfg.static_dir + "/scram", "/scram/");
    files.mount(cfg.static_dir + "/libcurl", "/libcurl/");
    files.mount(cfg.static_dir + "/baremux", "/baremux/");
    files.add_generated("/app-config.js", app_config_js(cfg),
                        "application/javascript; charset=utf-8", "no-cache");

    HostnamePolicy policy(cfg.hostname_blacklist_regex);

    // One thread on purpose: no locks, predictable CPU use on small hosts.
    boost::asio::io_context ioc{1};
    auto server = std::make_shared<HttpServer>(ioc, cfg, files, policy);
    if (!server->listen()) return 1;

    boost::asio::signal_set signals(ioc, SIGINT, SIGTERM);
    signals.async_wait([&](boost::system::error_code, int) {
        std::cout << "shutting down\n";
        server->stop();
        ioc.stop();
    });

    std::cout << "Scramjet server listening on " << cfg.host << ":" << cfg.port
              << " (" << files.count() << " static files in memory)\n";
    ioc.run();
    return 0;
}
