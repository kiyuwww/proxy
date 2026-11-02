#pragma once
#include <boost/asio.hpp>
#include <regex>
#include <vector>
#include "config.hpp"

// Decides whether a resolved destination address may be contacted.
// Blocks loopback / private / link-local / multicast ranges by default so the
// proxy cannot be used to reach the hosting platform's internal services.
bool is_address_allowed(const boost::asio::ip::address& addr, const Config& cfg);

// Compiled hostname blacklist (regex, matched against the requested hostname).
class HostnamePolicy {
public:
    explicit HostnamePolicy(const std::vector<std::string>& patterns);
    bool blocked(const std::string& hostname) const;
private:
    std::vector<std::regex> rules_;
};
