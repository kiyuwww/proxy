#include "wisp_session.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <vector>

namespace {
const bool kDebug = std::getenv("WISP_DEBUG") != nullptr;
}  // namespace

namespace {

// Wisp packet types.
constexpr std::uint8_t kConnect = 0x01, kData = 0x02, kContinue = 0x03, kClose = 0x04;
// Close reasons (subset of the spec).
constexpr std::uint8_t kReasonVoluntary = 0x02, kReasonNetworkError = 0x03;
constexpr std::uint8_t kReasonNoResponse = 0x43, kReasonTransferTimeout = 0x47;
constexpr std::uint8_t kReasonHostBlocked = 0x48, kReasonUnreachable = 0x42;
constexpr std::uint8_t kReasonThrottled = 0x49, kReasonUnknown = 0x01;
// Flow control: receive window advertised to the client.
constexpr std::uint32_t kStreamWindow = 128;

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

WispSession::WispSession(ws_stream ws, const Config& cfg, const HostnamePolicy& policy, SharedState& shared)
    : ws_(std::move(ws)),
      cfg_(cfg),
      policy_(policy),
      shared_(shared),
      resolver_(ws_.get_executor()),
      sweep_timer_(ws_.get_executor()) {
    ++shared_.sessions;
}

WispSession::~WispSession() {
    --shared_.sessions;
}

void WispSession::start() {
    if (kDebug) std::cerr << "wisp: session started\n";
    ws_.binary(true);
    ws_.auto_fragment(false);   // one frame per message: no extra splitting work
    ws_.read_message_max(cfg_.max_ws_message_bytes);
    websocket::stream_base::timeout t = websocket::stream_base::timeout::suggested(beast::role_type::server);
    t.idle_timeout = std::chrono::seconds(60);  // server-side pings detect dead clients
    ws_.set_option(t);

    // Wisp v1 handshake: the FIRST message must be CONTINUE on stream 0.
    // The browser client (libcurl-transport) opens streams on the first message it
    // receives and reads its send window from that CONTINUE; an INFO packet first
    // would leave the window unset and data would never be sent.
    send_frame(packet(kContinue, 0, le32(kStreamWindow)));

    sweep();
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
            auto d = self->buf_.data();   // flat_buffer: one contiguous region
            self->on_message(std::string_view(static_cast<const char*>(d.data()), d.size()));
        }
        self->buf_.consume(self->buf_.size());
        if (!self->closing_) self->read_loop();
    });
}

void WispSession::on_message(std::string_view msg) {
    if (msg.size() < 5) return;
    auto type = static_cast<std::uint8_t>(msg[0]);
    std::uint32_t sid = read_le32(msg.data() + 1);
    if (kDebug) std::cerr << "wisp: packet type=" << int(type) << " sid=" << sid << " len=" << msg.size() << "\n";
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
    if (streams_.size() >= cfg_.max_streams_per_session || shared_.streams >= cfg_.max_total_streams) {
        send_close(sid, kReasonThrottled);
        return;
    }
    // UDP is intentionally unsupported; hostnames and ports are checked before any DNS lookup.
    if (stype != 0x01 || host.empty() || port == 0 || policy_.blocked(host) ||
        std::find(cfg_.blocked_ports.begin(), cfg_.blocked_ports.end(), static_cast<int>(port)) != cfg_.blocked_ports.end()) {
        send_close(sid, kReasonHostBlocked);
        return;
    }

    auto s = std::make_shared<TcpStream>(ws_.get_executor(), sid);
    s->session = weak_from_this();
    streams_[sid] = s;
    ++shared_.streams;
    resolve_and_connect(s, host, port);
}

void WispSession::resolve_and_connect(const std::shared_ptr<TcpStream>& s, const std::string& host, std::uint16_t port) {
    // Cache hit: no getaddrinfo at all (it runs on a helper thread and is slow on a shared CPU).
    if (const auto* cached = shared_.dns.find(host)) {
        std::vector<tcp::endpoint> eps;
        for (const auto& a : *cached) eps.emplace_back(a, port);
        connect_to(s, std::move(eps));
        return;
    }
    auto self = shared_from_this();
    resolver_.async_resolve(host, std::to_string(port),
        [self, s, host, port](error_code ec, tcp::resolver::results_type results) {
            if (s->closed) return;
            if (ec) {
                if (kDebug) std::cerr << "wisp: dns lookup failed\n";
                self->close_stream(s->id, kReasonUnreachable);
                return;
            }
            std::vector<asio::ip::address> addrs;
            std::vector<tcp::endpoint> eps;
            for (const auto& r : results) {
                addrs.push_back(r.endpoint().address());
                eps.push_back(r.endpoint());
            }
            self->shared_.dns.put(host, std::move(addrs));   // unfiltered; the policy runs on every use
            self->connect_to(s, std::move(eps));
        });
}

void WispSession::connect_to(const std::shared_ptr<TcpStream>& s, std::vector<tcp::endpoint> candidates) {
    // Keep only addresses the policy allows (blocks localhost, private, metadata IPs).
    auto eps = std::make_shared<std::vector<tcp::endpoint>>();
    for (const auto& e : candidates)
        if (is_address_allowed(e.address(), cfg_)) eps->push_back(e);
    if (eps->empty()) {
        if (kDebug) std::cerr << "wisp: destination blocked by policy\n";
        close_stream(s->id, kReasonHostBlocked);
        return;
    }
    // Try IPv4 first: many hosts have no working IPv6 route, and a hung IPv6
    // attempt would otherwise eat the whole connect timeout.
    std::stable_partition(eps->begin(), eps->end(), [](const tcp::endpoint& e) { return e.address().is_v4(); });

    auto self = shared_from_this();
    asio::async_connect(s->socket, *eps,
        [self, s, eps](error_code ec2, const tcp::endpoint&) {
            if (s->closed) return;
            if (ec2) {
                if (kDebug) std::cerr << "wisp: connect failed: " << ec2.message() << "\n";
                self->close_stream(s->id, kReasonNetworkError);
                return;
            }
            s->connected = true;
            s->last_active = std::chrono::steady_clock::now();
            error_code ignore;
            s->socket.set_option(tcp::no_delay(true), ignore);
            self->read_next(s);
            self->do_write(s);  // flush anything the client sent during connect
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
            s->last_active = std::chrono::steady_clock::now();
            // Next read happens only after this chunk is written to the websocket: backpressure.
            self->send_frame(packet(kData, s->id, std::string_view(s->rbuf.data(), n)),
                             [self, s]() { self->read_next(s); });
        });
}

void WispSession::enqueue_write(const std::shared_ptr<TcpStream>& s, std::string data) {
    // Hard memory bounds: a peer that stops reading must not make us buffer without limit.
    if (s->pending_bytes + data.size() > cfg_.max_stream_pending_bytes ||
        pending_total_ + data.size() > cfg_.max_session_pending_bytes ||
        shared_.pending_bytes + data.size() > cfg_.max_total_pending_bytes) {
        close_stream(s->id, kReasonThrottled);
        return;
    }
    s->pending_bytes += data.size();
    pending_total_ += data.size();
    shared_.pending_bytes += data.size();
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
            std::size_t n = s->wq.front().size();
            s->wq.pop_front();
            s->pending_bytes -= n;
            self->pending_total_ -= std::min(self->pending_total_, n);
            self->shared_.pending_bytes -= std::min(self->shared_.pending_bytes, n);
            s->last_active = std::chrono::steady_clock::now();
            ++s->written_count;
            // Every 64 packets, tell the client how much room is left (same window as wisp-js).
            if (s->written_count % 64 == 0) {
                auto remaining = kStreamWindow - static_cast<std::uint32_t>(std::min<std::size_t>(s->wq.size(), kStreamWindow));
                self->send_frame(packet(kContinue, s->id, le32(remaining)));
            }
            self->do_write(s);
        });
}

// One sweep per session replaces per-stream timers: it enforces the connect timeout
// (DNS + TCP handshake) and the idle timeout of established streams.
void WispSession::sweep() {
    if (closing_) return;
    auto now = std::chrono::steady_clock::now();
    std::vector<std::pair<std::uint32_t, std::uint8_t>> expired;
    for (const auto& [sid, s] : streams_) {
        if (!s->connected) {
            if (now - s->created > std::chrono::seconds(cfg_.connect_timeout_sec))
                expired.emplace_back(sid, kReasonNoResponse);
        } else if (now - s->last_active > std::chrono::seconds(cfg_.stream_idle_timeout_sec)) {
            expired.emplace_back(sid, kReasonTransferTimeout);
        }
    }
    for (auto& [sid, reason] : expired) close_stream(sid, reason);

    auto self = shared_from_this();
    sweep_timer_.expires_after(std::chrono::seconds(streams_.empty() ? 15 : 3));
    sweep_timer_.async_wait([self](error_code ec) {
        if (!ec) self->sweep();
    });
}

// Releases one stream's resources and its share of the global counters.
void WispSession::drop_stream(const std::shared_ptr<TcpStream>& s) {
    s->closed = true;
    error_code ignore;
    s->socket.close(ignore);
    pending_total_ -= std::min(pending_total_, s->pending_bytes);
    shared_.pending_bytes -= std::min(shared_.pending_bytes, s->pending_bytes);
    s->pending_bytes = 0;
    s->wq.clear();
    if (shared_.streams) --shared_.streams;
}

void WispSession::close_stream(std::uint32_t sid, std::uint8_t reason) {
    auto it = streams_.find(sid);
    if (it == streams_.end()) return;
    auto s = it->second;
    streams_.erase(it);
    drop_stream(s);
    if (reason) send_close(sid, reason);
}

void WispSession::send_close(std::uint32_t sid, std::uint8_t reason) {
    std::string payload(1, static_cast<char>(reason));
    send_frame(packet(kClose, sid, payload));
}

void WispSession::close_all() {
    if (closing_) return;
    closing_ = true;
    for (auto& [sid, s] : streams_) drop_stream(s);
    streams_.clear();
    error_code ignore;
    resolver_.cancel();
    sweep_timer_.cancel(ignore);
    beast::get_lowest_layer(ws_).close();
}
