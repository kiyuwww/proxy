#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// Runtime configuration, read from environment variables
// (a local .env file is loaded too, but never overrides real env vars).
struct Config {
    std::string host = "0.0.0.0";
    std::uint16_t port = 8080;

    std::string public_dir = "public";   // served at /
    std::string static_dir = "static";   // scram/, libcurl/, baremux/ subfolders

    // PostgreSQL connection string, e.g. postgres://user:pass@host:5432/postgres?sslmode=require
    std::string database_url;

    // Session cookie.
    bool cookie_secure = true;           // set COOKIE_SECURE=0 only for plain-http local tests
    int session_days = 30;

    // Behind a reverse proxy (Render, Cloudflare) the real client address comes from headers.
    bool trust_proxy = true;

    // Accounts and abuse protection (all counters live in memory and reset on restart).
    int max_users = 2000;                // hard cap on accounts, protects the free database
    int register_per_ip_per_hour = 10;
    int login_failures_per_user_ip = 10; // per (ip, username) per window
    int login_failures_per_user = 40;    // per username from any address
    int login_failures_per_ip = 30;      // per address, any username
    int login_window_sec = 900;

    // Destination policy (SSRF protection and abuse prevention for public hosting).
    bool allow_private_ips = false;
    bool allow_loopback_ips = false;
    std::vector<std::string> hostname_blacklist_regex = {"example\\.com"};
    // Mail, SSH, Telnet, SMB, RDP: common abuse targets that get free hosting accounts suspended.
    std::vector<int> blocked_ports = {22, 23, 25, 139, 445, 465, 587, 2525, 3389};

    // Resource limits, sized for 0.1 vCPU / 512 MB.
    std::size_t max_streams_per_session = 128;
    std::size_t max_total_streams = 512;          // across all sessions (file descriptors)
    std::size_t max_sessions = 64;
    std::size_t max_ws_message_bytes = 128 * 1024;        // Wisp DATA frames are <= ~64 KiB
    std::size_t max_stream_pending_bytes = 8 * 1024 * 1024;   // client->server data waiting per stream
    std::size_t max_session_pending_bytes = 48 * 1024 * 1024; // ... and per websocket session
    std::size_t max_total_pending_bytes = 160 * 1024 * 1024;  // ... and across the whole server
    std::size_t worker_queue_limit = 24;          // pending database/hash jobs before answering 503
    int dns_ttl_sec = 120;
    int connect_timeout_sec = 10;
    int stream_idle_timeout_sec = 300;
    int http_header_timeout_sec = 15;
};

// Loads .env (if present) into the environment, then builds Config.
// Throws std::runtime_error if required settings are missing.
Config load_config();
