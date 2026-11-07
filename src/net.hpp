#pragma once
#include <chrono>
#include <cstdint>
#include <string>
#include <stdexcept>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
using socket_handle = SOCKET;
constexpr socket_handle invalid_socket = INVALID_SOCKET;
#else
#include <sys/types.h>
using socket_handle = int;
constexpr socket_handle invalid_socket = -1;
#endif
namespace net {
struct Runtime { Runtime(); ~Runtime(); Runtime(const Runtime&) = delete; Runtime& operator=(const Runtime&) = delete; };
struct Socket {
  socket_handle fd = invalid_socket;
  Socket() = default;
  explicit Socket(socket_handle f) : fd(f) {}
  ~Socket();
  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;
  Socket(Socket&& other) noexcept;
  Socket& operator=(Socket&& other) noexcept;
  bool valid() const { return fd != invalid_socket; }
};
Socket listen_loopback(uint16_t port);
Socket accept_one(const Socket& listener);
Socket connect_loopback(uint16_t port, int timeout_ms = 750);
void send_line(const Socket& socket, const std::string& line);
std::string read_line(const Socket& socket, int timeout_ms = 750, size_t limit = 4096);
std::string request(uint16_t port, const std::string& msg, int timeout_ms = 750);
std::string error_text();
std::string random_hex(size_t bytes = 16);
std::string sha256_hex(const std::string& data);
std::string hmac_sha256_hex(const std::string& key, const std::string& message);
bool constant_time_equal(const std::string& a, const std::string& b);
std::string timestamp_utc();
std::string sanitize(std::string s);
std::string get_arg(int argc, char** argv, const std::string& flag, const std::string& fallback);
uint16_t parse_port(const std::string& value);
}
