#include "http_server.hpp"

#include <iostream>
#include <string_view>

#include "wisp_session.hpp"

namespace {

constexpr std::string_view kCoop = "same-origin";
constexpr std::string_view kCoep = "require-corp";

void add_security_headers(http::response<http::string_body>& res) {
    // Required for the Scramjet/libcurl wasm stack (cross-origin isolation).
    res.set("Cross-Origin-Opener-Policy", kCoop);
    res.set("Cross-Origin-Embedder-Policy", kCoep);
    res.set("X-Content-Type-Options", "nosniff");
}

std::string_view path_of(std::string_view target) {
    auto q = target.find('?');
    return q == std::string_view::npos ? target : target.substr(0, q);
}

bool accepts_gzip(const http::request<http::empty_body>& req) {
    auto ae = req[http::field::accept_encoding];
    return ae.find("gzip") != std::string_view::npos;
}

}  // namespace

// ---------------------------------------------------------------- HttpServer

HttpServer::HttpServer(asio::io_context& ioc, const Config& cfg, const StaticFiles& files, const HostnamePolicy& policy)
    : ioc_(ioc), cfg_(cfg), files_(files), policy_(policy), acceptor_(ioc) {}

bool HttpServer::listen() {
    boost::system::error_code ec;
    auto addr = asio::ip::make_address(cfg_.host, ec);
    if (ec) { std::cerr << "invalid HOST: " << cfg_.host << "\n"; return false; }
    tcp::endpoint ep(addr, cfg_.port);
    acceptor_.open(ep.protocol(), ec);
    acceptor_.set_option(asio::socket_base::reuse_address(true), ec);
    acceptor_.bind(ep, ec);
    if (!ec) acceptor_.listen(asio::socket_base::max_listen_connections, ec);
    if (ec) { std::cerr << "listen failed: " << ec.message() << "\n"; return false; }
    do_accept();
    return true;
}

void HttpServer::stop() {
    boost::system::error_code ec;
    acceptor_.close(ec);
}

void HttpServer::do_accept() {
    auto self = shared_from_this();
    acceptor_.async_accept(ioc_, [self](boost::system::error_code ec, tcp::socket socket) {
        if (!ec) {
            std::make_shared<HttpSession>(std::move(socket), self->cfg_, self->files_, self->policy_)->run();
        }
        if (self->acceptor_.is_open()) self->do_accept();
    });
}

// ---------------------------------------------------------------- HttpSession

HttpSession::HttpSession(tcp::socket socket, const Config& cfg, const StaticFiles& files, const HostnamePolicy& policy)
    : stream_(std::move(socket)), cfg_(cfg), files_(files), policy_(policy) {}

void HttpSession::run() { do_read(); }

void HttpSession::do_read() {
    parser_.emplace();
    parser_->header_limit(16 * 1024);
    parser_->body_limit(0);  // no request bodies are needed
    stream_.expires_after(std::chrono::seconds(cfg_.http_header_timeout_sec));
    auto self = shared_from_this();
    http::async_read(stream_, buf_, *parser_,
        [self](boost::system::error_code ec, std::size_t) {
            if (ec) {
                // Keep-alive connection closed by the client, or a malformed request.
                boost::system::error_code ignore;
                self->stream_.socket().shutdown(tcp::socket::shutdown_both, ignore);
                return;
            }
            self->handle_request();
        });
}

void HttpSession::handle_request() {
    const auto& req = parser_->get();

    if (websocket::is_upgrade(req)) {
        if (req.method() == http::verb::get && path_of(req.target()).size() >= 6 &&
            path_of(req.target()).substr(path_of(req.target()).size() - 6) == "/wisp/") {
            upgrade_to_wisp();
        } else {
            http::response<http::string_body> res{http::status::not_found, req.version()};
            res.body() = "Not found";
            res.prepare_payload();
            send(std::move(res), false);
        }
        return;
    }

    serve_static(req);
}

void HttpSession::upgrade_to_wisp() {
    auto req = std::make_shared<http::request<http::empty_body>>(parser_->release());
    stream_.expires_never();
    auto ws = std::make_shared<ws_stream>(std::move(stream_));
    // Capture long-lived references only: this HttpSession may be gone by the time accept completes.
    const Config& cfg = cfg_;
    const HostnamePolicy& policy = policy_;
    ws->async_accept(*req, [ws, req, &cfg, &policy](boost::system::error_code ec) {
        if (ec) return;
        auto session = std::make_shared<WispSession>(std::move(*ws), cfg, policy);
        session->start();
    });
}

void HttpSession::serve_static(const http::request<http::empty_body>& req) {
    bool keep_alive = req.keep_alive();

    if (req.method() != http::verb::get) {
        http::response<http::string_body> res{http::status::method_not_allowed, req.version()};
        res.set(http::field::allow, "GET");
        res.body() = "Method not allowed";
        res.prepare_payload();
        send(std::move(res), keep_alive);
        return;
    }

    std::string_view path = path_of(req.target());
    const Asset* asset = files_.find(path);

    if (!asset) {
        // Same behavior as the original app: 404 with the styled error page.
        const Asset* page = files_.find("/404.html");
        http::response<http::string_body> res{http::status::not_found, req.version()};
        res.set(http::field::content_type, "text/html; charset=utf-8");
        res.set(http::field::cache_control, "no-cache");
        res.body() = page ? page->body : std::string("404 Not Found");
        res.prepare_payload();
        add_security_headers(res);
        send(std::move(res), keep_alive);
        return;
    }

    http::response<http::string_body> res{http::status::ok, req.version()};
    res.set(http::field::content_type, asset->content_type);
    res.set(http::field::cache_control, asset->cache_control);
    res.set(http::field::etag, asset->etag);
    res.set(http::field::vary, "Accept-Encoding");

    if (req[http::field::if_none_match] == asset->etag) {
        res.result(http::status::not_modified);
    } else if (!asset->body_gzip.empty() && accepts_gzip(req)) {
        res.set(http::field::content_encoding, "gzip");
        res.body() = asset->body_gzip;
    } else {
        res.body() = asset->body;
    }
    if (res.result() == http::status::not_modified) res.body().clear();
    res.prepare_payload();
    add_security_headers(res);
    send(std::move(res), keep_alive);
}

void HttpSession::send(http::response<http::string_body> res, bool keep_alive) {
    res.keep_alive(keep_alive);
    auto sp = std::make_shared<http::response<http::string_body>>(std::move(res));
    stream_.expires_after(std::chrono::seconds(30));
    auto self = shared_from_this();
    http::async_write(stream_, *sp,
        [self, sp, keep_alive](boost::system::error_code ec, std::size_t) {
            if (ec || !keep_alive) {
                boost::system::error_code ignore;
                self->stream_.socket().shutdown(tcp::socket::shutdown_send, ignore);
                return;
            }
            self->do_read();
        });
}
