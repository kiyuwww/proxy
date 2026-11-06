#pragma once
#include <boost/asio.hpp>

#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>

// One background thread for everything that can block: database round trips and
// password hashing. The network thread (io_context) never waits on them, so static
// files and the proxy keep flowing while a login is being verified.
// The queue is bounded: when it is full submit() returns false and the caller
// answers 503 instead of piling up work on a 0.1 vCPU instance.
class Worker {
public:
    Worker(boost::asio::io_context& ioc, std::size_t limit) : ioc_(ioc), limit_(limit) {
        thread_ = std::thread([this] { loop(); });
    }
    ~Worker() {
        {
            std::lock_guard<std::mutex> lk(m_);
            stop_ = true;
        }
        cv_.notify_all();
        if (thread_.joinable()) thread_.join();
    }
    Worker(const Worker&) = delete;
    Worker& operator=(const Worker&) = delete;

    // job runs on the worker thread; done(result) runs on the io_context thread.
    template <class R>
    bool submit(std::function<R()> job, std::function<void(R)> done) {
        auto task = [this, job = std::move(job), done = std::move(done)]() mutable {
            R r = job();   // job must not throw (it converts errors into R)
            boost::asio::post(ioc_, [done = std::move(done), r = std::move(r)]() mutable { done(std::move(r)); });
        };
        return push(std::move(task));
    }

    // Fire and forget (cleanup jobs).
    bool submit_void(std::function<void()> job) { return push(std::move(job)); }

private:
    bool push(std::function<void()> task) {
        {
            std::lock_guard<std::mutex> lk(m_);
            if (stop_ || q_.size() >= limit_) return false;
            q_.push_back(std::move(task));
        }
        cv_.notify_one();
        return true;
    }
    void loop() {
        for (;;) {
            std::function<void()> t;
            {
                std::unique_lock<std::mutex> lk(m_);
                cv_.wait(lk, [this] { return stop_ || !q_.empty(); });
                if (q_.empty()) return;   // stop requested and drained
                t = std::move(q_.front());
                q_.pop_front();
            }
            try { t(); } catch (...) {}
        }
    }

    boost::asio::io_context& ioc_;
    std::size_t limit_;
    std::mutex m_;
    std::condition_variable cv_;
    std::deque<std::function<void()>> q_;
    bool stop_ = false;
    std::thread thread_;
};
