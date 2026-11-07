#include "net.hpp"
#include <iostream>
#include <string>
int main(int argc, char** argv) {
  try {
    net::Runtime runtime;
    const auto port=net::parse_port(net::get_arg(argc,argv,"--port","48392"));
    const auto state=net::get_arg(argc,argv,"--state","healthy");
    if(state!="healthy" && state!="compromised") throw std::runtime_error("state must be healthy or compromised");
    const auto lab_key=net::get_arg(argc,argv,"--lab-key","LAB_SHARED_ATTEST_KEY");
    const auto listener=net::listen_loopback(port);
    std::cout << "MOCK_AGENT_READY port=" << port << " state=" << state << std::endl;
    while(true) {
      auto peer=net::accept_one(listener);
      try {
        const auto msg=net::read_line(peer);
        if(msg=="PING") net::send_line(peer,"PONG");
        else if(msg.rfind("ATTEST|",0)==0) {
          const auto challenge=msg.substr(7);
          const auto verdict=(state=="healthy"?"LAB_OK":"LAB_CHANGED");
          const auto mac=net::hmac_sha256_hex(lab_key,challenge+"|"+state+"|"+verdict);
          net::send_line(peer,"ATTEST|"+state+"|"+verdict+"|"+mac);
        }
        else net::send_line(peer,"ERR|UNKNOWN_REQUEST");
      } catch(const std::exception& e) { std::cerr << "mock_agent request_error=" << e.what() << '\n'; }
    }
  } catch(const std::exception& e) { std::cerr << "mock_agent fatal=" << e.what() << '\n'; return 1; }
}
