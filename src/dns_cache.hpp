#pragma once
#include <boost/asio/ip/address.hpp>

#include <chrono>
#include <string>
#include <unordered_map>
#include <vector>

// Small TTL cache for DNS answers (event-loop thread only, no locking).
// A page load opens dozens of connections to the same few hosts; without the cache
// each one costs a getaddrinfo round trip on a slow, shared CPU.
class DnsCache {
public:
    DnsCache(int ttl_sec, std::size_t max_entries) : ttl_(ttl_sec), max_(max_entries) {}

    const std::vector<boost::asio::ip::address>* find(const std::string& host) {
        auto it = map_.find(host);
        if (it == map_.end()) return nullptr;
        if (std::chrono::steady_clock::now() > it->second.expires) { map_.erase(it); return nullptr; }
        return &it->second.addrs;
    }
    void put(const std::string& host, std::vector<boost::asio::ip::address> addrs) {
        if (ttl_ <= 0 || addrs.empty()) return;
        if (map_.size() >= max_) map_.clear();
        map_[host] = Entry{std::move(addrs), std::chrono::steady_clock::now() + std::chrono::seconds(ttl_)};
    }

private:
    struct Entry {
        std::vector<boost::asio::ip::address> addrs;
        std::chrono::steady_clock::time_point expires;
    };
    int ttl_;
    std::size_t max_;
    std::unordered_map<std::string, Entry> map_;
};
