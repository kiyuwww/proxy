#include "http_server.hpp"

#include <iostream>
#include <map>
#include <string_view>

#include "wisp_session.hpp"

namespace {

constexpr std::string_view kSessionCookie = "sid";
constexpr std::size_t kMaxBodyBytes = 4096;
constexpr std::size_t kMaxHttpConnections = 256;

void add_security_headers(http::response<http::string_body>& res) {
    // Needed by the Scramjet/libcurl wasm stack (cross-origin isolation).
    res.set("Cross-Origin-Opener-Policy", "same-origin");
    res.set("Cross-Origin-Embedder-Policy", "require-corp");
    res.set("X-Content-Type-Options", "nosniff");
    res.set("Referrer-Policy", "no-referrer");
}

std::string_view path_of(std::string_view target) {
    auto q = target.find('?');
    return q == std::string_view::npos ? target : target.substr(0, q);
}

bool accepts_gzip(const request_t& req) {
    return req[http::field::accept_encoding].find("gzip") != std::string_view::npos;
}

// Reads "sid=<token>" from the Cookie header.
std::string session_token(const request_t& req) {
    std::string_view cookies = req[http::field::cookie];
    std::size_t pos = 0;
    while (pos < cookies.size()) {
        auto end = cookies.find(';', pos);
        std::string_view part = cookies.substr(pos, end == std::string_view::npos ? end : end - pos);
        while (!part.empty() && part.front() == ' ') part.remove_prefix(1);
        if (part.size() > kSessionCookie.size() + 1 && part.substr(0, kSessionCookie.size()) == kSessionCookie &&
            part[kSessionCookie.size()] == '=')
            return std::string(part.substr(kSessionCookie.size() + 1));
        if (end == std::string_view::npos) break;
        pos = end + 1;
    }
    return {};
}

// application/x-www-form-urlencoded parser (keys and values are url-decoded).
std::map<std::string, std::string> parse_form(std::string_view body) {
    auto hex = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    auto decode = [&](std::string_view s) {
        std::string out;
        for (std::size_t i = 0; i < s.size(); ++i) {
            if (s[i] == '+') out.push_back(' ');
            else if (s[i] == '%' && i + 2 < s.size() && hex(s[i + 1]) >= 0 && hex(s[i + 2]) >= 0) {
                out.push_back(static_cast<char>((hex(s[i + 1]) << 4) | hex(s[i + 2])));
                i += 2;
            } else out.push_back(s[i]);
        }
        return out;
    };
    std::map<std::string, std::string> out;
    std::size_t pos = 0;
    while (pos <= body.size()) {
        auto amp = body.find('&', pos);
        auto part = body.substr(pos, amp == std::string_view::npos ? amp : amp - pos);
        auto eq = part.find('=');
        if (!part.empty()) {
            out[decode(part.substr(0, eq))] = eq == std::string_view::npos ? "" : decode(part.substr(eq + 1));
        }
        if (amp == std::string_view::npos) break;
        pos = amp + 1;
    }
    return out;
}

std::string json_escape(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '"' || c == '\\') { out.push_back('\\'); out.push_back(c); }
        else if (static_cast<unsigned char>(c) < 0x20) { out += ' '; }
        else out.push_back(c);
    }
    return out;
}

std::string cookie_value(const std::string& token, int max_age, bool secure) {
    std::string c = "sid=" + token + "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" + std::to_string(max_age);
    if (secure) c += "; Secure";
    return c;
}

}  // namespace

// ---------------------------------------------------------------- HttpServer

HttpServer::HttpServer(asio::io_context& ioc, AppContext ctx)
    : ioc_(ioc), ctx_(ctx), acceptor_(ioc) {}

bool HttpServer::listen() {
    boost::system::error_code ec;
    auto addr = asio::ip::make_address(ctx_.cfg.host, ec);
    if (ec) { std::cerr << "invalid HOST\n"; return false; }
    tcp::endpoint ep(addr, ctx_.cfg.port);
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
        if (!self->acceptor_.is_open()) return;
        if (!ec) {
            if (self->ctx_.shared.http_conns >= kMaxHttpConnections) {
                boost::system::error_code ignore;   // shed load instead of running out of descriptors
                socket.close(ignore);
            } else {
                std::make_shared<HttpSession>(std::move(socket), self->ctx_)->run();
            }
        }
        // EMFILE/ENFILE and friends: back off briefly instead of spinning at 100% CPU.
        if (ec == asio::error::no_descriptors || ec == asio::error::no_buffer_space ||
            ec == boost::asio::error::make_error_code(boost::asio::error::basic_errors::no_memory)) {
            auto t = std::make_shared<asio::steady_timer>(self->ioc_, std::chrono::milliseconds(200));
            t->async_wait([self, t](boost::system::error_code) { if (self->acceptor_.is_open()) self->do_accept(); });
            return;
        }
        self->do_accept();
    });
}

// ---------------------------------------------------------------- HttpSession

HttpSession::HttpSession(tcp::socket socket, AppContext ctx)
    : stream_(std::move(socket)), ctx_(ctx) {
    boost::system::error_code ec;
    auto ep = stream_.socket().remote_endpoint(ec);
    peer_ip_ = ec ? std::string("unknown") : ep.address().to_string();
    ++ctx_.shared.http_conns;
}

HttpSession::~HttpSession() {
    --ctx_.shared.http_conns;
}

std::string HttpSession::client_ip(const request_t& req) const {
    if (ctx_.cfg.trust_proxy) {
        // Render/Cloudflare put the original client first in X-Forwarded-For.
        std::string_view xff = req["X-Forwarded-For"];
        auto comma = xff.find(',');
        std::string first(xff.substr(0, comma));
        while (!first.empty() && first.front() == ' ') first.erase(first.begin());
        while (!first.empty() && first.back() == ' ') first.pop_back();
        boost::system::error_code ec;
        auto a = asio::ip::make_address(first, ec);
        if (!ec) return a.to_string();   // normalized, so the key cannot be padded with junk
    }
    return peer_ip_;
}

void HttpSession::run() { do_read(); }

void HttpSession::do_read() {
    parser_.emplace();
    parser_->header_limit(16 * 1024);
    parser_->body_limit(kMaxBodyBytes);
    stream_.expires_after(std::chrono::seconds(ctx_.cfg.http_header_timeout_sec));
    auto self = shared_from_this();
    http::async_read(stream_, buf_, *parser_,
        [self](boost::system::error_code ec, std::size_t) {
            if (ec) {
                boost::system::error_code ignore;
                self->stream_.socket().shutdown(tcp::socket::shutdown_both, ignore);
                return;
            }
            try {
                self->handle_request();
            } catch (const std::exception& e) {
                std::cerr << "request error: " << e.what() << "\n";
                self->send_json(http::status::internal_server_error, R"({"error":"server error"})", false);
            }
        });
}

void HttpSession::handle_request() {
    auto req = std::make_shared<request_t>(parser_->release());
    std::string_view path = path_of(req->target());

    // WebSocket for the proxy: only for logged-in users.
    if (websocket::is_upgrade(*req)) {
        bool is_wisp = path.size() >= 6 && path.substr(path.size() - 6) == "/wisp/";
        if (!is_wisp || req->method() != http::verb::get) {
            send_json(http::status::not_found, R"({"error":"not found"})", false);
            return;
        }
        if (ctx_.shared.sessions >= ctx_.cfg.max_sessions) {
            send_json(http::status::service_unavailable, R"({"error":"server is full"})", false);
            return;
        }
        auto self = shared_from_this();
        ctx_.auth.validate(session_token(*req), [self, req](Auth::Validation v) {
            if (v.busy) { self->send_json(http::status::service_unavailable, R"({"error":"try again"})", false); return; }
            if (!v.user) { self->send_json(http::status::unauthorized, R"({"error":"login required"})", false); return; }
            if (self->ctx_.shared.sessions >= self->ctx_.cfg.max_sessions) {
                self->send_json(http::status::service_unavailable, R"({"error":"server is full"})", false);
                return;
            }
            self->upgrade_to_wisp(std::move(*req));
        });
        return;
    }

    if (path == "/healthz") {   // cheap liveness probe: no database, no files
        http::response<http::string_body> res{http::status::ok, req->version()};
        res.set(http::field::content_type, "text/plain");
        res.set(http::field::cache_control, "no-store");
        res.body() = "ok";
        res.prepare_payload();
        send_response(std::move(res), req->keep_alive(), req->method() == http::verb::head);
        return;
    }

    if (path.substr(0, 5) == "/api/") {
        handle_api(*req);
        return;
    }
    serve_static(*req);
}

void HttpSession::upgrade_to_wisp(request_t req) {
    auto stored = std::make_shared<request_t>(std::move(req));
    stream_.expires_never();
    auto ws = std::make_shared<ws_stream>(std::move(stream_));
    AppContext ctx = ctx_;
    ws->async_accept(*stored, [ws, stored, ctx](boost::system::error_code ec) {
        if (ec) return;
        auto session = std::make_shared<WispSession>(std::move(*ws), ctx.cfg, ctx.policy, ctx.shared);
        session->start();
    });
}

void HttpSession::handle_api(const request_t& req) {
    const bool keep_alive = req.keep_alive();
    std::string_view path = path_of(req.target());

    // Same-origin check for state-changing requests (basic CSRF protection).
    if (req.method() == http::verb::post && req[http::field::origin] != "") {
        std::string proto = std::string(req["X-Forwarded-Proto"]);
        if (proto.empty()) proto = "http";
        std::string expected = proto + "://" + std::string(req[http::field::host]);
        if (std::string(req[http::field::origin]) != expected) {
            send_json(http::status::forbidden, R"({"error":"bad origin"})", false);
            return;
        }
    }

    auto self = shared_from_this();
    const bool secure = ctx_.cfg.cookie_secure;
    const int cookie_age = ctx_.cfg.session_days * 86400;

    if (path == "/api/me" && req.method() == http::verb::get) {
        ctx_.auth.validate(session_token(req), [self, keep_alive](Auth::Validation v) {
            if (v.busy) { self->send_json(http::status::service_unavailable, R"({"error":"try again"})", false); return; }
            if (!v.user) { self->send_json(http::status::unauthorized, R"({"error":"not logged in"})", keep_alive); return; }
            self->send_json(http::status::ok, R"({"username":")" + json_escape(*v.user) + R"("})", keep_alive);
        });
        return;
    }

    if (path == "/api/logout" && req.method() == http::verb::post) {
        ctx_.auth.logout(session_token(req));   // cache entry is dropped now; the DELETE runs in the background
        send_json(http::status::ok, R"({"ok":true})", keep_alive, cookie_value("", 0, secure));
        return;
    }

    if ((path == "/api/register" || path == "/api/login") && req.method() == http::verb::post) {
        auto form = parse_form(req.body());
        std::string user = form.count("username") ? form["username"] : "";
        std::string pass = form.count("password") ? form["password"] : "";
        auto done = [self, keep_alive, secure, cookie_age](Auth::Result r) {
            if (!r.ok) {
                self->send_json(static_cast<http::status>(r.http_status),
                                R"({"error":")" + json_escape(r.error) + R"("})", keep_alive && r.http_status < 500);
                return;
            }
            self->send_json(http::status::ok, R"({"username":")" + json_escape(r.username) + R"("})", keep_alive,
                            cookie_value(r.token, cookie_age, secure));
        };
        std::string ip = client_ip(req);
        if (path == "/api/register") ctx_.auth.register_user(user, pass, ip, done);
        else ctx_.auth.login(user, pass, ip, done);
        return;
    }

    send_json(http::status::not_found, R"({"error":"not found"})", keep_alive);
}

void HttpSession::serve_static(const request_t& req) {
    const bool keep_alive = req.keep_alive();
    const bool head = req.method() == http::verb::head;

    if (req.method() != http::verb::get && !head) {
        http::response<http::string_body> res{http::status::method_not_allowed, req.version()};
        res.set(http::field::allow, "GET, HEAD");
        res.body() = "Method not allowed";
        res.prepare_payload();
        send_response(std::move(res), keep_alive);
        return;
    }

    std::string_view path = path_of(req.target());
    const Asset* asset = ctx_.files.find(path);

    if (!asset) {
        const Asset* page = ctx_.files.find("/404.html");
        http::response<http::string_body> res{http::status::not_found, req.version()};
        res.set(http::field::content_type, "text/html; charset=utf-8");
        res.set(http::field::cache_control, "no-cache");
        res.body() = page ? page->body : std::string("404 Not Found");
        res.prepare_payload();
        add_security_headers(res);
        send_response(std::move(res), keep_alive, head);
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
    res.prepare_payload();
    add_security_headers(res);
    send_response(std::move(res), keep_alive, head);
}

void HttpSession::send_json(http::status status, const std::string& json, bool keep_alive,
                            const std::optional<std::string>& set_cookie) {
    http::response<http::string_body> res{status, 11};
    res.set(http::field::content_type, "application/json; charset=utf-8");
    res.set(http::field::cache_control, "no-store");
    if (set_cookie) res.set(http::field::set_cookie, *set_cookie);
    res.body() = json;
    res.prepare_payload();
    add_security_headers(res);
    send_response(std::move(res), keep_alive);
}

void HttpSession::send_response(http::response<http::string_body> res, bool keep_alive, bool head_only) {
    res.keep_alive(keep_alive);
    if (ctx_.cfg.cookie_secure) res.set("Strict-Transport-Security", "max-age=31536000");
    if (head_only) res.body().clear();   // headers keep the Content-Length of the full body
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
