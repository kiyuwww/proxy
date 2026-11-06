#pragma once
#include <cstddef>
#include "dns_cache.hpp"

// Counters and caches shared by all websocket sessions (event-loop thread only).
struct SharedState {
    explicit SharedState(int dns_ttl) : dns(dns_ttl, 512) {}
    DnsCache dns;
    std::size_t sessions = 0;
    std::size_t streams = 0;
    std::size_t http_conns = 0;
    std::size_t pending_bytes = 0;   // client->server bytes queued, all sessions
};
