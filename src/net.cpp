#include "net.hpp"
#include <array>
#include <iomanip>
#include <sstream>
#include <random>
#include <ctime>
#include <algorithm>
#include <cstring>
#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cerrno>
#include <fcntl.h>
#include <sys/select.h>
#endif
namespace {
void close_socket(socket_handle fd) {
  if(fd == invalid_socket) return;
#ifdef _WIN32
  closesocket(fd);
#else
  ::close(fd);
#endif
}
void wait_socket(socket_handle fd, bool write, int ms) {
  fd_set fds; FD_ZERO(&fds); FD_SET(fd, &fds);
  timeval tv{}; tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
#ifdef _WIN32
  const int n = select(0, write ? nullptr : &fds, write ? &fds : nullptr, nullptr, &tv);
#else
  const int n = select(fd + 1, write ? nullptr : &fds, write ? &fds : nullptr, nullptr, &tv);
#endif
  if(n == 0) throw std::runtime_error("network timeout");
  if(n < 0) throw std::runtime_error("select failed: " + net::error_text());
}
}
namespace net {
Runtime::Runtime() {
#ifdef _WIN32
  WSADATA wsa{};
  if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0) throw std::runtime_error("WSAStartup failed");
#endif
}
Runtime::~Runtime() {
#ifdef _WIN32
  WSACleanup();
#endif
}
Socket::~Socket() { close_socket(fd); }
Socket::Socket(Socket&& other) noexcept : fd(other.fd) { other.fd = invalid_socket; }
Socket& Socket::operator=(Socket&& other) noexcept {
  if(this != &other) { close_socket(fd); fd=other.fd; other.fd=invalid_socket; }
  return *this;
}
std::string error_text() {
#ifdef _WIN32
  return std::to_string(WSAGetLastError());
#else
  return std::strerror(errno);
#endif
}
Socket listen_loopback(uint16_t port) {
  Socket sock(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
  if(!sock.valid()) throw std::runtime_error("socket: " + error_text());
  int reuse = 1;
  setsockopt(sock.fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
  sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if(::bind(sock.fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
    throw std::runtime_error("bind port " + std::to_string(port) + ": " + error_text());
  if(::listen(sock.fd, 32) != 0) throw std::runtime_error("listen: " + error_text());
  return sock;
}
Socket accept_one(const Socket& listener) {
  socket_handle raw = ::accept(listener.fd, nullptr, nullptr);
  if(raw == invalid_socket) throw std::runtime_error("accept: " + error_text());
  return Socket(raw);
}
Socket connect_loopback(uint16_t port, int timeout_ms) {
  Socket sock(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
  if(!sock.valid()) throw std::runtime_error("socket: " + error_text());
#ifdef _WIN32
  u_long mode=1; ioctlsocket(sock.fd, FIONBIO, &mode);
#else
  const int original = fcntl(sock.fd, F_GETFL, 0);
  if(original < 0 || fcntl(sock.fd, F_SETFL, original | O_NONBLOCK) < 0)
    throw std::runtime_error("fcntl failed");
#endif
  sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_port=htons(port); addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
  const int rc = ::connect(sock.fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
  if(rc != 0) {
#ifdef _WIN32
    if(WSAGetLastError() != WSAEWOULDBLOCK) throw std::runtime_error("connect failed: " + error_text());
#else
    if(errno != EINPROGRESS) throw std::runtime_error("connect failed: " + error_text());
#endif
    wait_socket(sock.fd, true, timeout_ms);
    int so_error=0;
#ifdef _WIN32
    int len=sizeof(so_error);
#else
    socklen_t len=sizeof(so_error);
#endif
    if(getsockopt(sock.fd, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_error), &len) != 0 || so_error != 0)
      throw std::runtime_error("connect failed or refused");
  }
#ifdef _WIN32
  mode=0; ioctlsocket(sock.fd, FIONBIO, &mode);
#else
  fcntl(sock.fd, F_SETFL, original);
#endif
  return sock;
}
void send_line(const Socket& sock, const std::string& line) {
  if(line.find('\n') != std::string::npos || line.size() > 4094) throw std::runtime_error("invalid outgoing frame");
  const std::string frame=line+"\n";
  size_t pos=0;
  while(pos < frame.size()) {
    wait_socket(sock.fd, true, 750);
    const auto remaining = static_cast<int>(frame.size() - pos);
    const auto sent=::send(sock.fd, frame.data()+pos, remaining, 0);
    if(sent <= 0) throw std::runtime_error("send failed: " + error_text());
    pos+=static_cast<size_t>(sent);
  }
}
std::string read_line(const Socket& sock, int timeout_ms, size_t limit) {
  auto deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(timeout_ms);
  std::string result;
  while(result.size() < limit) {
    const auto remaining=std::chrono::duration_cast<std::chrono::milliseconds>(deadline-std::chrono::steady_clock::now()).count();
    if(remaining <= 0) throw std::runtime_error("network timeout");
    wait_socket(sock.fd, false, static_cast<int>(remaining));
    char byte=0;
    const auto n=::recv(sock.fd, &byte, 1, 0);
    if(n <= 0) throw std::runtime_error("peer closed connection");
    if(byte=='\n') return result;
    if(byte=='\r' || byte=='\0') throw std::runtime_error("invalid frame character");
    result.push_back(byte);
  }
  throw std::runtime_error("frame exceeds limit");
}
std::string request(uint16_t port, const std::string& msg, int timeout_ms) {
  auto s=connect_loopback(port, timeout_ms); send_line(s,msg); return read_line(s,timeout_ms);
}
std::string random_hex(size_t bytes) {
  std::random_device device;
  std::ostringstream out;
  for(size_t i=0;i<bytes;i++) out << std::hex << std::setw(2) << std::setfill('0') << (device() & 0xffu);
  return out.str();
}
namespace {
struct Sha256 {
  uint32_t h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
  static uint32_t ror(uint32_t x,uint32_t n){ return (x>>n)|(x<<(32-n)); }
  void block(const unsigned char* p){
    static const uint32_t k[64]={
      0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
      0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
      0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
      0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
      0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    uint32_t w[64];
    for(int i=0;i<16;i++) w[i]=uint32_t(p[i*4])<<24|uint32_t(p[i*4+1])<<16|uint32_t(p[i*4+2])<<8|uint32_t(p[i*4+3]);
    for(int i=16;i<64;i++){ uint32_t s0=ror(w[i-15],7)^ror(w[i-15],18)^(w[i-15]>>3), s1=ror(w[i-2],17)^ror(w[i-2],19)^(w[i-2]>>10); w[i]=w[i-16]+s0+w[i-7]+s1; }
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for(int i=0;i<64;i++){
      uint32_t S1=ror(e,6)^ror(e,11)^ror(e,25), ch=(e&f)^(~e&g), t1=hh+S1+ch+k[i]+w[i];
      uint32_t S0=ror(a,2)^ror(a,13)^ror(a,22), maj=(a&b)^(a&c)^(b&c), t2=S0+maj;
      hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
  }
  std::array<unsigned char,32> digest(const std::string& msg){
    uint64_t total=msg.size();
    size_t off=0;
    while(msg.size()-off>=64){ block(reinterpret_cast<const unsigned char*>(msg.data()+off)); off+=64; }
    unsigned char tail[128]={0}; size_t rem=msg.size()-off;
    std::memcpy(tail,msg.data()+off,rem);
    tail[rem]=0x80;
    size_t pad=(rem<56)?64:128;
    uint64_t bits=total*8;
    for(int i=0;i<8;i++) tail[pad-1-size_t(i)]=static_cast<unsigned char>(bits>>(8*i));
    block(tail); if(pad==128) block(tail+64);
    std::array<unsigned char,32> out{};
    for(int i=0;i<8;i++){ out[size_t(i*4)]=static_cast<unsigned char>(h[i]>>24); out[size_t(i*4+1)]=static_cast<unsigned char>(h[i]>>16); out[size_t(i*4+2)]=static_cast<unsigned char>(h[i]>>8); out[size_t(i*4+3)]=static_cast<unsigned char>(h[i]); }
    return out;
  }
};
std::string to_hex(const unsigned char* p, size_t n){
  std::ostringstream out;
  for(size_t i=0;i<n;i++) out<<std::hex<<std::setw(2)<<std::setfill('0')<<static_cast<unsigned>(p[i]);
  return out.str();
}
}
std::string sha256_hex(const std::string& data){ Sha256 s; auto d=s.digest(data); return to_hex(d.data(),d.size()); }
std::string hmac_sha256_hex(const std::string& key, const std::string& message){
  std::string k=key;
  if(k.size()>64){ Sha256 s; auto d=s.digest(k); k.assign(reinterpret_cast<const char*>(d.data()),d.size()); }
  k.resize(64,'\0');
  std::string ipad(64,0),opad(64,0);
  for(size_t i=0;i<64;i++){ ipad[i]=static_cast<char>(static_cast<unsigned char>(k[i])^0x36u); opad[i]=static_cast<char>(static_cast<unsigned char>(k[i])^0x5cu); }
  Sha256 inner; auto id=inner.digest(ipad+message);
  Sha256 outer; auto od=outer.digest(opad+std::string(reinterpret_cast<const char*>(id.data()),id.size()));
  return to_hex(od.data(),od.size());
}
bool constant_time_equal(const std::string& a, const std::string& b){
  if(a.size()!=b.size()) return false;
  unsigned char diff=0;
  for(size_t i=0;i<a.size();i++) diff|=static_cast<unsigned char>(a[i])^static_cast<unsigned char>(b[i]);
  return diff==0;
}
std::string timestamp_utc() {
  const auto t=std::time(nullptr);
  std::tm info{};
#ifdef _WIN32
  gmtime_s(&info,&t);
#else
  gmtime_r(&t,&info);
#endif
  char buffer[32]{}; std::strftime(buffer,sizeof(buffer),"%Y-%m-%dT%H:%M:%SZ",&info);
  return buffer;
}
std::string sanitize(std::string s) {
  for(char& c:s) if(c=='\"'||c=='\\'||c=='\r'||c=='\n'||static_cast<unsigned char>(c)<32u) c='_';
  return s;
}
std::string get_arg(int argc, char** argv, const std::string& flag, const std::string& fallback) {
  for(int i=1;i+1<argc;i++) if(argv[i] == flag) return argv[i+1];
  return fallback;
}
uint16_t parse_port(const std::string& value) {
  size_t used=0; const auto n=std::stoul(value,&used);
  if(used!=value.size() || n<1024 || n>65535) throw std::runtime_error("port must be 1024..65535");
  return static_cast<uint16_t>(n);
}
}
