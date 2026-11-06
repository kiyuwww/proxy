#pragma once
#include <map>
#include <string>
#include <string_view>
#include <vector>

// All static files are read once at startup and kept in RAM (gzip copies too),
// so each request is a map lookup plus a memcpy-free write. Nothing is read from
// disk per request and path traversal is impossible: only known keys exist.
struct Asset {
    std::string content_type;
    std::string etag;
    std::string body;          // identity encoding
    std::string body_gzip;     // empty if not compressible / not smaller
    std::string cache_control;
};

class StaticFiles {
public:
    // Mounts a directory at a URL prefix ("/" or "/scram/" ...).
    void mount(const std::string& dir, const std::string& url_prefix);
    // Adds a file generated in memory (no disk read).
    void add_generated(const std::string& url_path, std::string content,
                       std::string content_type, std::string cache_control);
    const Asset* find(std::string_view url_path) const;
    std::size_t count() const { return assets_.size(); }

private:
    void add_file(const std::string& url_path, const std::string& fs_path);
    std::map<std::string, Asset, std::less<>> assets_;
};
