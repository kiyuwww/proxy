#include "static_files.hpp"

#include <zlib.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

namespace fs = std::filesystem;

namespace {

std::string content_type_for(const std::string& path) {
    auto dot = path.rfind('.');
    std::string ext = dot == std::string::npos ? "" : path.substr(dot + 1);
    if (ext == "html") return "text/html; charset=utf-8";
    if (ext == "css") return "text/css; charset=utf-8";
    if (ext == "js" || ext == "mjs" || ext == "cjs") return "application/javascript; charset=utf-8";
    if (ext == "json") return "application/json; charset=utf-8";
    if (ext == "wasm") return "application/wasm";
    if (ext == "png") return "image/png";
    if (ext == "ico") return "image/x-icon";
    if (ext == "svg") return "image/svg+xml";
    if (ext == "txt") return "text/plain; charset=utf-8";
    return "application/octet-stream";
}

bool is_compressible(const std::string& ct) {
    return ct.rfind("text/", 0) == 0 || ct.find("javascript") != std::string::npos ||
           ct.find("json") != std::string::npos || ct.find("svg") != std::string::npos ||
           ct == "application/wasm";
}

// gzip-compress; returns empty when it does not help.
std::string gzip(const std::string& in) {
    z_stream zs{};
    if (deflateInit2(&zs, 6, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
        return {};
    std::string out(deflateBound(&zs, in.size()) + 32, '\0');
    zs.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data()));
    zs.avail_in = static_cast<uInt>(in.size());
    zs.next_out = reinterpret_cast<Bytef*>(out.data());
    zs.avail_out = static_cast<uInt>(out.size());
    int rc = deflate(&zs, Z_FINISH);
    std::size_t produced = zs.total_out;
    deflateEnd(&zs);
    if (rc != Z_STREAM_END) return {};
    out.resize(produced);
    return out.size() < in.size() ? out : std::string{};
}

std::string etag_of(const std::string& data) {
    // FNV-1a 64-bit: cheap and deterministic for ETag validation.
    std::uint64_t h = 1469598103934665603ull;
    for (unsigned char c : data) { h ^= c; h *= 1099511628211ull; }
    char buf[32];
    std::snprintf(buf, sizeof buf, "\"%016llx\"", static_cast<unsigned long long>(h));
    return buf;
}

std::string cache_for(const std::string& url_path) {
    // Versioned vendor bundles get a short public cache; app files revalidate.
    if (url_path.rfind("/scram/", 0) == 0 || url_path.rfind("/libcurl/", 0) == 0 ||
        url_path.rfind("/baremux/", 0) == 0)
        return "public, max-age=3600";
    return "no-cache";
}

std::string slurp(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return {};
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

// precompressed: contents of a "<file>.gz" sidecar made at build time (empty = none).
void store(std::map<std::string, Asset, std::less<>>& m, const std::string& url_path,
           std::string body, const std::string& ct, const std::string& cc, std::string precompressed) {
    Asset a;
    a.content_type = ct;
    a.cache_control = cc;
    a.etag = etag_of(body);
    if (!precompressed.empty() && precompressed.size() < body.size()) a.body_gzip = std::move(precompressed);
    else if (is_compressible(ct)) a.body_gzip = gzip(body);   // fallback; costs CPU at startup
    a.body = std::move(body);
    m[url_path] = std::move(a);
}

}  // namespace

void StaticFiles::add_file(const std::string& url_path, const std::string& fs_path) {
    std::ifstream probe(fs_path, std::ios::binary);
    if (!probe) return;
    probe.close();
    store(assets_, url_path, slurp(fs_path), content_type_for(fs_path), cache_for(url_path),
          slurp(fs_path + ".gz"));
}

void StaticFiles::mount(const std::string& dir, const std::string& url_prefix) {
    std::error_code ec;
    if (!fs::is_directory(dir, ec)) {
        std::cerr << "warning: directory not found, skipped: " << dir << "\n";
        return;
    }
    for (auto it = fs::recursive_directory_iterator(dir, ec);
         it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) break;
        if (!it->is_regular_file()) continue;
        auto rel = fs::relative(it->path(), dir).generic_string();
        // "<file>.gz" next to "<file>" is a build-time sidecar, not a separate asset.
        if (rel.size() > 3 && rel.compare(rel.size() - 3, 3, ".gz") == 0 &&
            fs::exists(it->path().string().substr(0, it->path().string().size() - 3), ec))
            continue;
        std::string url = url_prefix + rel;
        // "/" + "index.html" -> serve the root as the index page too.
        add_file(url, it->path().string());
        if (url_prefix == "/" && rel == "index.html") add_file("/", it->path().string());
    }
}

void StaticFiles::add_generated(const std::string& url_path, std::string content,
                                std::string content_type, std::string cache_control) {
    store(assets_, url_path, std::move(content), content_type, cache_control, {});
}

const Asset* StaticFiles::find(std::string_view url_path) const {
    auto it = assets_.find(url_path);
    return it == assets_.end() ? nullptr : &it->second;
}
