#include "wisp_session.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <vector>

namespace {

// Wisp packet types.
constexpr std::uint8_t kConnect = 0x01, kData = 0x02, kContinue = 0x03, kClose = 0x04, kInfo = 0x05;
// Close reasons (subset of the spec).
constexpr std::uint8_t kReasonVoluntary = 0x02, kReasonNetworkError = 0x03;
constexpr std::uint8_t kReasonNoResponse = 0x43, kReasonTransferTimeout = 0x47;
constexpr std::uint8_t kReasonHostBlocked = 0x48, kReasonUnreachable = 0x42;
constexpr std::uint8_t kReasonThrottled = 0x49, kReasonUnknown = 0x01;
// Flow control: receive window advertised to the client.
constexpr std::uint32_t kStreamWindow = 128;
constexpr std::size_t kMaxPendingWrites = 512;

std::string packet(std::uint8_t type, std::uint32_t sid, std::string_view payload) {
    std::string p;
    p.reserve(5 + payload.size());
    p.push_back(static_cast<char>(type));
    for (int i = 0; i < 4; ++i) p.push_back(static_cast<char>((sid >> (8 * i)) & 0xFF));  // little-endian
    p.append(payload.data(), payload.size());
    return p;
}

std::string le32(std::uint32_t v) {
    std::string s(4, '\0');
    for (int i = 0; i < 4; ++i) s[i] = static_cast<char>((v >> (8 * i)) & 0xFF);
    return s;
}

std::uint32_t read_le32(const char* p) {
    std::uint32_t v = 0;
    for (int i = 3; i >= 0; --i) v = (v << 8) | static_cast<unsigned char>(p[i]);
    return v;
}

std::uint16_t read_le16(const char* p) {
    return static_cast<std::uint16_t>(static_cast<unsigned char>(p[0]) |
                                      (static_cast<unsigned char>(p[1]) << 8));
}

std::string trim(std::string s) {
    auto ok = [](char c) { return c != ' ' && c != '\t' && c != '\0' && c != '\r' && c != '\n'; };
    auto b = std::find_if(s.begin(), s.end(), ok);
    auto e = std::find_if(s.rbegin(), s.rend(), ok).base();
    return (b < e) ? std::string(b, e) : std::string{};
}

}  // namespace

WispSession::WispSession(ws_stream ws, const Config& cfg, const HostnamePolicy& policy)
    : ws_(std::move(ws)),
      cfg_(cfg),
      policy_(policy),
      resolver_(ws_.get_executor()) {}

void WispSession::start() {
    ws_.binary(true);
    ws_.read_message_max(cfg_.max_ws_message_bytes);
    websocket::stream_base::timeout t = websocket::stream_base::timeout::suggested(beast::role_type::server);
    t.idle_timeout = std::chrono::seconds(60);  // server-side pings detect dead clients
    ws_.set_option(t);

    // v2 server hello: version 2.0 with no extensions (UDP and MOTD are disabled).
    std::string info;
    info.push_back(2);
    info.push_back(0);
    send_frame(packet(kInfo, 0, info));
    // Initial flow-control window for the whole connection.
    send_frame(packet(kContinue, 0, le32(kStreamWindow)));

    read_loop();
}

void WispSession::send_frame(std::string frame, std::function<void()> on_written) {
    if (closing_) return;
    out_.push_back(OutFrame{std::move(frame), std::move(on_written)});
    pump_writes();
}

void WispSession::pump_writes() {
    if (writing_ || out_.empty()) return;
    writing_ = true;
    auto self = shared_from_this();
    ws_.async_write(asio::buffer(out_.front().data), [self](error_code ec, std::size_t) {
        self->writing_ = false;
        if (ec) { self->close_all(); return; }
        auto cb = std::move(self->out_.front().on_written);
        self->out_.pop_front();
        self->pump_writes();
        if (cb) cb();
    });
}

void WispSession::read_loop() {
    auto self = shared_from_this();
    ws_.async_read(buf_, [self](error_code ec, std::size_t) {
        if (ec) { self->close_all(); return; }
        if (!self->ws_.got_text()) {
            std::string msg = beast::buffers_to_string(self->buf_.data());
            self->on_message(msg);
        }
        self->buf_.consume(self->buf_.size());
        if (!self->closing_) self->read_loop();
    });
}

void WispSession::on_message(const std::string& msg) {
    if (msg.size() < 5) return;
    auto type = static_cast<std::uint8_t>(msg[0]);
    std::uint32_t sid = read_le32(msg.data() + 1);
    std::string_view payload(msg.data() + 5, msg.size() - 5);

    switch (type) {
        case kConnect: {
            if (payload.size() < 3) return;
            auto stype = static_cast<std::uint8_t>(payload[0]);
            std::uint16_t port = read_le16(payload.data() + 1);
            handle_connect(sid, stype, port, trim(std::string(payload.substr(3))));
            break;
        }
        case kData: {
            auto it = streams_.find(sid);
            if (it == streams_.end()) return;
            enqueue_write(it->second, std::string(payload));
            break;
        }
        case kClose:
            close_stream(sid, 0);
            break;
        default:
            break;  // CONTINUE / INFO from the client are not expected after the handshake
    }
}

void WispSession::handle_connect(std::uint32_t sid, std::uint8_t stype, std::uint16_t port, std::string host) {
    if (streams_.count(sid)) { send_close(sid, kReasonUnknown); return; }
    if (streams_.size() >= cfg_.max_streams_per_session) { send_close(sid, kReasonThrottled); return; }
    // UDP is intentionally unsupported; hostnames are checked before any DNS lookup.
    if (stype != 0x01 || host.empty() || policy_.blocked(host)) { send_close(sid, kReasonHostBlocked); return; }

    auto s = std::make_shared<TcpStream>(ws_.get_executor(), sid);
    s->session = weak_from_this();
    streams_[sid] = s;
    s->timer.expires_after(std::chrono::seconds(cfg_.connect_timeout_sec));
    arm_timer(s);
    resolve_and_connect(s, host, port);
}

void WispSession::resolve_and_connect(const std::shared_ptr<TcpStream>& s, const std::string& host, std::uint16_t port) {
    auto self = shared_from_this();
    resolver_.async_resolve(host, std::to_string(port),
        [self, s](error_code ec, tcp::resolver::results_type results) {
            if (s->closed) return;
            if (ec) { self->close_stream(s->id, kReasonUnreachable); return; }

            // Keep only addresses the policy allows (blocks localhost, private, metadata IPs).
            auto eps = std::make_shared<std::vector<tcp::endpoint>>();
            for (const auto& r : results)
                if (is_address_allowed(r.endpoint().address(), self->cfg_))
                    eps->push_back(r.endpoint());
            if (eps->empty()) { self->close_stream(s->id, kReasonHostBlocked); return; }

            asio::async_connect(s->socket, *eps,
                [self, s, eps](error_code ec2, const tcp::endpoint&) {
                    if (s->closed) return;
                    if (ec2) { self->close_stream(s->id, kReasonNetworkError); return; }
                    s->connected = true;
                    error_code ignore;
                    s->socket.set_option(tcp::no_delay(true), ignore);
                    self->touch(s);
                    self->read_next(s);
                    self->do_write(s);  // flush anything the client sent during connect
                });
        });
}

void WispSession::read_next(const std::shared_ptr<TcpStream>& s) {
    if (s->closed) return;
    auto self = shared_from_this();
    s->socket.async_read_some(asio::buffer(s->rbuf),
        [self, s](error_code ec, std::size_t n) {
            if (s->closed) return;
            if (ec) {
                self->close_stream(s->id, ec == asio::error::eof ? kReasonVoluntary : kReasonNetworkError);
                return;
            }
            self->touch(s);
            // Next read happens only after this chunk is written to the websocket: backpressure.
            self->send_frame(packet(kData, s->id, std::string_view(s->rbuf.data(), n)),
                             [self, s]() { self->read_next(s); });
        });
}

void WispSession::enqueue_write(const std::shared_ptr<TcpStream>& s, std::string data) {
    if (s->wq.size() >= kMaxPendingWrites) { close_stream(s->id, kReasonThrottled); return; }
    s->wq.push_back(std::move(data));
    if (s->connected && !s->writing) do_write(s);
}

void WispSession::do_write(const std::shared_ptr<TcpStream>& s) {
    if (s->closed || !s->connected || s->wq.empty()) { s->writing = false; return; }
    s->writing = true;
    auto self = shared_from_this();
    asio::async_write(s->socket, asio::buffer(s->wq.front()),
        [self, s](error_code ec, std::size_t) {
            if (s->closed) return;
            s->writing = false;
            if (ec) { self->close_stream(s->id, kReasonNetworkError); return; }
            s->wq.pop_front();
            self->touch(s);
            ++s->written_count;
            // Every 64 packets, tell the client how much room is left (same window as wisp-js).
            if (s->written_count % 64 == 0) {
                auto remaining = kStreamWindow - static_cast<std::uint32_t>(std::min<std::size_t>(s->wq.size(), kStreamWindow));
                self->send_frame(packet(kContinue, s->id, le32(remaining)));
            }
            self->do_write(s);
        });
}

// The timer doubles as connect timeout and idle timeout. Changing the deadline
// cancels the pending wait; we re-arm on cancellation and act only on real expiry.
void WispSession::arm_timer(const std::shared_ptr<TcpStream>& s) {
    auto self = shared_from_this();
    s->timer.async_wait([self, s](error_code ec) {
        if (s->closed) return;
        if (ec == asio::error::operation_aborted) { self->arm_timer(s); return; }
        self->close_stream(s->id, s->connected ? kReasonTransferTimeout : kReasonNoResponse);
    });
}

void WispSession::touch(const std::shared_ptr<TcpStream>& s) {
    if (s->connected) s->timer.expires_after(std::chrono::seconds(cfg_.stream_idle_timeout_sec));
}

void WispSession::close_stream(std::uint32_t sid, std::uint8_t reason) {
    auto it = streams_.find(sid);
    if (it == streams_.end()) return;
    auto s = it->second;
    streams_.erase(it);
    s->closed = true;
    error_code ignore;
    s->socket.close(ignore);
    s->timer.cancel(ignore);
    if (reason) send_close(sid, reason);
}

void WispSession::send_close(std::uint32_t sid, std::uint8_t reason) {
    std::string payload(1, static_cast<char>(reason));
    send_frame(packet(kClose, sid, payload));
}

void WispSession::close_all() {
    if (closing_) return;
    closing_ = true;
    for (auto& [sid, s] : streams_) {
        s->closed = true;
        error_code ignore;
        s->socket.close(ignore);
        s->timer.cancel(ignore);
    }
    streams_.clear();
    error_code ignore;
    resolver_.cancel();
    beast::get_lowest_layer(ws_).close();
}
