// Scramjet server (C++): web UI, username/password accounts, and the Wisp
// websocket endpoint (/wisp/) that the browser uses to reach the internet.
//
// Threads: the network thread (io_context) serves files and relays TCP; one worker
// thread does database round trips and password hashing, so neither can stall the other.
#include <sys/resource.h>

#include <csignal>
#include <iostream>

#include <boost/asio.hpp>

#include "auth.hpp"
#include "config.hpp"
#include "db.hpp"
#include "http_server.hpp"
#include "net_policy.hpp"
#include "shared_state.hpp"
#include "static_files.hpp"
#include "worker.hpp"

namespace {
void raise_fd_limit() {
    rlimit rl{};
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur < rl.rlim_max) {
        rl.rlim_cur = rl.rlim_max;
        setrlimit(RLIMIT_NOFILE, &rl);
    }
}
}  // namespace

int main() {
    std::signal(SIGPIPE, SIG_IGN);
    raise_fd_limit();

    Config cfg;
    try {
        cfg = load_config();
    } catch (const std::exception& e) {
        std::cerr << "config error: " << e.what() << "\n";
        return 1;
    }

    // Static files first: they are what a visitor needs while a sleeping free instance wakes up.
    StaticFiles files;
    files.mount(cfg.public_dir, "/");
    files.mount(cfg.static_dir + "/scram", "/scram/");
    files.mount(cfg.static_dir + "/libcurl", "/libcurl/");
    files.mount(cfg.static_dir + "/baremux", "/baremux/");

    HostnamePolicy policy(cfg.hostname_blacklist_regex);

    // One network thread on purpose: no locks, predictable CPU use on small hosts.
    boost::asio::io_context ioc{1};
    Db db(cfg.database_url);
    Worker worker(ioc, cfg.worker_queue_limit);
    Auth auth(db, cfg, worker);
    SharedState shared(cfg.dns_ttl_sec);

    // Warm up the database connection (and create tables) in the background: the port
    // is already open, a slow or sleeping database no longer delays startup.
    worker.submit_void([&db]() {
        try { db.connect_and_migrate(); std::cout << "database ready" << std::endl; }
        catch (const std::exception& e) { std::cerr << e.what() << " (will retry on first request)\n"; }
    });
    auth.cleanup_expired();

    AppContext ctx{cfg, files, policy, auth, shared};
    auto server = std::make_shared<HttpServer>(ioc, ctx);
    if (!server->listen()) return 1;

    bool stopping = false;
    boost::asio::signal_set signals(ioc, SIGINT, SIGTERM);
    signals.async_wait([&](boost::system::error_code, int) {
        std::cout << "shutting down" << std::endl;
        stopping = true;
        server->stop();
        ioc.stop();
    });

    // Hourly housekeeping: expired sessions out of the (1 GB) database.
    boost::asio::steady_timer housekeeping(ioc);
    std::function<void()> tick = [&]() {
        housekeeping.expires_after(std::chrono::hours(1));
        housekeeping.async_wait([&](boost::system::error_code ec) {
            if (ec) return;
            auth.cleanup_expired();
            tick();
        });
    };
    tick();

    std::cout << "Scramjet server listening on " << cfg.host << ":" << cfg.port
              << " (" << files.count() << " static files in memory)" << std::endl;

    // A handler exception must not take the whole proxy down for every user.
    while (!stopping) {
        try {
            ioc.run();
            break;
        } catch (const std::exception& e) {
            std::cerr << "unhandled error in event loop: " << e.what() << "\n";
        } catch (...) {
            std::cerr << "unhandled unknown error in event loop\n";
        }
    }
    return 0;
}
