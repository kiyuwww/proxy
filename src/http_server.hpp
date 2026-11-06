#pragma once
#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <memory>
#include <optional>
#include "auth.hpp"
#include "config.hpp"
#include "net_policy.hpp"
#include "shared_state.hpp"
#include "static_files.hpp"

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
using tcp = asio::ip::tcp;
using request_t = http::request<http::string_body>;

// Long-lived objects shared by all connections (owned by main).
struct AppContext {
    const Config& cfg;
    const StaticFiles& files;
    const HostnamePolicy& policy;
    Auth& auth;
    SharedState& shared;
};

// Accepts connections and dispatches them.
class HttpServer : public std::enable_shared_from_this<HttpServer> {
public:
    HttpServer(asio::io_context& ioc, AppContext ctx);
    bool listen();
    void stop();

private:
    void do_accept();

    asio::io_context& ioc_;
    AppContext ctx_;
    tcp::acceptor acceptor_;
};

class HttpSession : public std::enable_shared_from_this<HttpSession> {
public:
    HttpSession(tcp::socket socket, AppContext ctx);
    ~HttpSession();
    void run();

private:
    std::string client_ip(const request_t& req) const;
    void do_read();
    void handle_request();
    void upgrade_to_wisp(request_t req);
    void handle_api(const request_t& req);
    void serve_static(const request_t& req);
    void send_response(http::response<http::string_body> res, bool keep_alive, bool head_only = false);
    void send_json(http::status status, const std::string& json, bool keep_alive,
                   const std::optional<std::string>& set_cookie = std::nullopt);

    beast::tcp_stream stream_;
    AppContext ctx_;
    std::string peer_ip_;
    beast::flat_buffer buf_;
    std::optional<http::request_parser<http::string_body>> parser_;
};
