#pragma once
#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <memory>
#include <optional>
#include "config.hpp"
#include "net_policy.hpp"
#include "static_files.hpp"

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
using tcp = asio::ip::tcp;

// Accepts connections and serves static files or upgrades /wisp/ to Wisp.
class HttpServer : public std::enable_shared_from_this<HttpServer> {
public:
    HttpServer(asio::io_context& ioc, const Config& cfg, const StaticFiles& files, const HostnamePolicy& policy);
    bool listen();
    void stop();

private:
    void do_accept();

    asio::io_context& ioc_;
    const Config& cfg_;
    const StaticFiles& files_;
    const HostnamePolicy& policy_;
    tcp::acceptor acceptor_;
};

class HttpSession : public std::enable_shared_from_this<HttpSession> {
public:
    HttpSession(tcp::socket socket, const Config& cfg, const StaticFiles& files, const HostnamePolicy& policy);
    void run();

private:
    void do_read();
    void handle_request();
    void upgrade_to_wisp();
    void serve_static(const http::request<http::empty_body>& req);
    void send(http::response<http::string_body> res, bool keep_alive);

    beast::tcp_stream stream_;
    const Config& cfg_;
    const StaticFiles& files_;
    const HostnamePolicy& policy_;
    beast::flat_buffer buf_;
    std::optional<http::request_parser<http::empty_body>> parser_;
};
