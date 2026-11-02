#pragma once
#include <cstdint>
#include <string>
#include <vector>

// Runtime configuration. Everything comes from environment variables
// (or from a local .env file, which never overrides real env vars).
struct Config {
    std::string host = "0.0.0.0";
    std::uint16_t port = 8080;

    std::string public_dir = "public";   // served at /
    std::string static_dir = "static";   // scram/, libcurl/, baremux/ subfolders

    // Supabase values are handed to the browser via /app-config.js.
    // Empty values disable the login box (the search still works).
    std::string supabase_url;
    std::string supabase_anon_key;

    // Destination policy (SSRF protection for public hosting).
    bool allow_private_ips = false;       // RFC1918, link-local, CGNAT, ...
    bool allow_loopback_ips = false;      // 127.0.0.0/8, ::1
    std::vector<std::string> hostname_blacklist_regex = {"example\\.com"};

    // Resource limits (keep free-tier RAM/CPU predictable).
    std::size_t max_streams_per_session = 256;
    std::size_t max_ws_message_bytes = 1 << 20;  // 1 MiB
    int connect_timeout_sec = 10;
    int stream_idle_timeout_sec = 300;
    int http_header_timeout_sec = 15;
};

// Loads .env (if present) into the process environment, then builds Config.
Config load_config();
