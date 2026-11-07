#include "net.hpp"
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <vector>
namespace {
std::vector<std::string> split(const std::string& s) {
  std::vector<std::string> p; size_t start=0;
  while(true) { const auto pos=s.find('|',start); p.push_back(s.substr(start,pos==std::string::npos?pos:pos-start)); if(pos==std::string::npos) break; start=pos+1; }
  return p;
}
}
int main(int argc, char** argv) {
  try {
    net::Runtime runtime;
    const auto port=net::parse_port(net::get_arg(argc,argv,"--gateway-port","48391"));
    const auto scenario=net::get_arg(argc,argv,"--scenario","normal");
    const int interval=std::stoi(net::get_arg(argc,argv,"--interval-ms","200"));
    if(interval<0 || interval>30000) throw std::runtime_error("invalid interval-ms");
    const auto hello=net::request(port,"HELLO");
    std::cout << "HELLO -> " << hello << '\n';
    const auto s=split(hello);
    if(s.size()!=4 || s[0]!="SESSION") return 2;
    std::string id=s[1],nonce=s[2],secret=s[3];
    auto beat=[&](unsigned seq, const std::string& claim, const std::string& use_nonce,
                  const std::string& sign_secret, const std::string& use_id) {
      const auto body=use_id+"|"+std::to_string(seq)+"|"+use_nonce+"|"+claim;
      const auto mac=net::hmac_sha256_hex(sign_secret,body);
      const auto frame="BEAT|"+body+"|"+mac;
      const auto response=net::request(port,frame);
      std::cout << "HEARTBEAT seq=" << seq << " -> " << response << std::endl;
      return response;
    };
    auto legit=[&](unsigned seq, const std::string& claim){ return beat(seq,claim,nonce,secret,id); };
    if(scenario=="normal") {
      for(unsigned seq=1;seq<=3;seq++) {
        const auto response=legit(seq,"healthy");
        const auto r=split(response);
        if(r.size()!=3 || r[0]!="ALLOW" || r[1]!=std::to_string(seq)) return 3;
        nonce=r[2];
        if(seq<3) std::this_thread::sleep_for(std::chrono::milliseconds(interval));
      }
      return 0;
    }
    if(scenario=="replay") { if(split(legit(1,"healthy"))[0]!="ALLOW") return 3; return legit(1,"healthy")=="BLOCK|NONCE_MISMATCH"?0:3; }
    if(scenario=="seq-gap") return legit(2,"healthy")=="BLOCK|REPLAY_OR_SEQUENCE_GAP"?0:3;
    if(scenario=="tamper") return legit(1,"compromised")=="BLOCK|CLIENT_INTEGRITY_MISMATCH"?0:3;
    if(scenario=="bad-nonce") return beat(1,"healthy","bad-token",secret,id)=="BLOCK|NONCE_MISMATCH"?0:3;
    if(scenario=="forged-mac") return beat(1,"healthy",nonce,"attacker-guessed-secret",id)=="BLOCK|MAC_INVALID"?0:3;
    if(scenario=="wrong-session") return beat(1,"healthy",nonce,secret,"unknown-session")=="BLOCK|UNKNOWN_SESSION"?0:3;
    if(scenario=="expired") { std::this_thread::sleep_for(std::chrono::milliseconds(interval)); return legit(1,"healthy")=="BLOCK|HEARTBEAT_TIMEOUT"?0:3; }
    std::cerr << "unknown scenario: " << scenario << '\n'; return 4;
  } catch(const std::exception& e) { std::cerr << "client fatal=" << e.what() << '\n'; return 1; }
}
