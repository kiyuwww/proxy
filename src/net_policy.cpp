#include "net_policy.hpp"

namespace asio = boost::asio;

namespace {

bool in_v4(std::uint32_t ip, std::uint32_t net, int prefix) {
    std::uint32_t mask = prefix == 0 ? 0 : (0xFFFFFFFFu << (32 - prefix));
    return (ip & mask) == (net & mask);
}

bool blocked_v4(std::uint32_t ip, const Config& cfg) {
    if (in_v4(ip, 0x7F000000u, 8)) return !cfg.allow_loopback_ips;      // 127.0.0.0/8
    if (in_v4(ip, 0x00000000u, 8)) return true;                          // 0.0.0.0/8
    if (in_v4(ip, 0xE0000000u, 4)) return true;                          // multicast 224/4
    if (in_v4(ip, 0xF0000000u, 4)) return true;                          // reserved/broadcast 240/4
    if (!cfg.allow_private_ips) {
        if (in_v4(ip, 0x0A000000u, 8)) return true;   // 10/8
        if (in_v4(ip, 0xAC100000u, 12)) return true;  // 172.16/12
        if (in_v4(ip, 0xC0A80000u, 16)) return true;  // 192.168/16
        if (in_v4(ip, 0xA9FE0000u, 16)) return true;  // 169.254/16 (cloud metadata)
        if (in_v4(ip, 0x64400000u, 10)) return true;  // 100.64/10 CGNAT
        if (in_v4(ip, 0xC0000000u, 24)) return true;  // 192.0.0/24
        if (in_v4(ip, 0xC6120000u, 15)) return true;  // 198.18/15 benchmarking
    }
    return false;
}

}  // namespace

bool is_address_allowed(const asio::ip::address& addr, const Config& cfg) {
    if (addr.is_v4()) return !blocked_v4(addr.to_v4().to_uint(), cfg);

    asio::ip::address_v6 v6 = addr.to_v6();
    if (v6.is_v4_mapped()) {
        return !blocked_v4(asio::ip::make_address_v4(
            asio::ip::v4_mapped, v6).to_uint(), cfg);
    }
    if (v6.is_unspecified()) return false;
    if (v6.is_loopback()) return cfg.allow_loopback_ips;
    if (v6.is_multicast()) return false;
    auto bytes = v6.to_bytes();
    if ((bytes[0] & 0xFE) == 0xFC) return cfg.allow_private_ips;  // fc00::/7 ULA
    if (bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80)             // fe80::/10
        return cfg.allow_private_ips;
    return true;
}

HostnamePolicy::HostnamePolicy(const std::vector<std::string>& patterns) {
    for (const auto& p : patterns)
        rules_.emplace_back(p, std::regex::ECMAScript | std::regex::icase | std::regex::optimize);
}

bool HostnamePolicy::blocked(const std::string& hostname) const {
    for (const auto& r : rules_)
        if (std::regex_search(hostname, r)) return true;
    return false;
}
