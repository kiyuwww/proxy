#pragma once
#include <array>
#include <chrono>
#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <deque>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include "config.hpp"
#include "net_policy.hpp"
#include "shared_state.hpp"

namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using error_code = boost::system::error_code;
using ws_stream = websocket::stream<beast::tcp_stream>;

class WispSession;

// One multiplexed TCP connection opened by the client over the websocket.
struct TcpStream {
    TcpStream(asio::any_io_executor ex, std::uint32_t id)
        : id(id), socket(ex), created(std::chrono::steady_clock::now()), last_active(created) {}

    std::uint32_t id;
    tcp::socket socket;
    // No per-stream timer: one sweep per session checks these (a timer reset per
    // packet costs more CPU than the packet itself on a 0.1 vCPU host).
    std::chrono::steady_clock::time_point created, last_active;
    std::array<char, 32768> rbuf{};       // server -> client read chunk
    std::deque<std::string> wq;           // client -> server payloads waiting to be written
    std::size_t pending_bytes = 0;        // bytes in wq
    bool connected = false;
    bool writing = false;
    bool closed = false;
    std::uint32_t written_count = 0;      // used for CONTINUE flow control
    std::weak_ptr<WispSession> session;
};

// Wisp protocol (v2 handshake, v1-compatible framing) over one websocket.
// Single-threaded by design: the whole server runs on one io_context thread,
// which avoids locking and suits small/free hosting instances.
class WispSession : public std::enable_shared_from_this<WispSession> {
public:
    WispSession(ws_stream ws, const Config& cfg, const HostnamePolicy& policy, SharedState& shared);
    ~WispSession();
    void start();

private:
    struct OutFrame {
        std::string data;
        std::function<void()> on_written;
    };

    void send_frame(std::string frame, std::function<void()> on_written = {});
    void pump_writes();
    void read_loop();
    void on_message(std::string_view msg);

    void handle_connect(std::uint32_t sid, std::uint8_t stype, std::uint16_t port, std::string host);
    void resolve_and_connect(const std::shared_ptr<TcpStream>& s, const std::string& host, std::uint16_t port);
    void connect_to(const std::shared_ptr<TcpStream>& s, std::vector<tcp::endpoint> eps);
    void read_next(const std::shared_ptr<TcpStream>& s);
    void enqueue_write(const std::shared_ptr<TcpStream>& s, std::string data);
    void do_write(const std::shared_ptr<TcpStream>& s);
    void sweep();
    void drop_stream(const std::shared_ptr<TcpStream>& s);

    void close_stream(std::uint32_t sid, std::uint8_t reason);  // reason 0 = silent
    void send_close(std::uint32_t sid, std::uint8_t reason);
    void close_all();

    ws_stream ws_;
    const Config& cfg_;
    const HostnamePolicy& policy_;
    SharedState& shared_;
    tcp::resolver resolver_;
    asio::steady_timer sweep_timer_;
    std::size_t pending_total_ = 0;   // client->server bytes queued across all streams
    beast::flat_buffer buf_;
    std::deque<OutFrame> out_;
    bool writing_ = false;
    bool closing_ = false;
    std::unordered_map<std::uint32_t, std::shared_ptr<TcpStream>> streams_;
};
