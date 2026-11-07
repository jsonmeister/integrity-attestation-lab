#include "net.hpp"
#include <chrono>
#include <fstream>
#include <iostream>
#include <sstream>
#include <unordered_map>
#include <vector>
#include <cstdint>

namespace {
using Clock=std::chrono::steady_clock;
struct Session {
  std::string nonce;
  std::string secret;
  uint64_t next_sequence=1;
  Clock::time_point last_heartbeat=Clock::now();
};
std::vector<std::string> parts(const std::string& input) {
  std::vector<std::string> output; size_t start=0;
  while(true) { const auto pos=input.find('|',start); output.push_back(input.substr(start,pos==std::string::npos?pos:pos-start)); if(pos==std::string::npos) break; start=pos+1; }
  return output;
}
uint64_t parse_sequence(const std::string& s) {
  if(s.empty() || s.size()>19) throw std::runtime_error("sequence malformed");
  for(const char c:s) if(c<'0'||c>'9') throw std::runtime_error("sequence malformed");
  size_t used=0; const auto n=std::stoull(s,&used);
  if(used!=s.size()) throw std::runtime_error("sequence malformed");
  return static_cast<uint64_t>(n);
}
struct Gateway {
  uint16_t agent_port;
  int ttl_ms;
  std::string lab_key;
  std::string audit_prev="GENESIS";
  std::ofstream audit;
  std::unordered_map<std::string,Session> sessions;
  void log(const std::string& kind, const std::string& reason, const std::string& session) {
    const auto time=net::timestamp_utc();
    std::ostringstream core;
    core << "\"time\":\"" << time << "\",\"event\":\"" << net::sanitize(kind)
         << "\",\"reason\":\"" << net::sanitize(reason) << "\",\"session\":\"" << net::sanitize(session)
         << "\",\"prev\":\"" << audit_prev << "\"";
    const auto hash=net::sha256_hex(audit_prev+"|"+core.str());
    audit_prev=hash;
    const std::string obj="{"+core.str()+",\"hash\":\""+hash+"\"}";
    std::cout << obj << std::endl;
    if(audit.is_open()) { audit << obj << '\n'; audit.flush(); }
  }
  bool check_agent(const std::string& challenge) {
    try {
      const auto reply=net::request(agent_port,"ATTEST|"+challenge,500);
      const auto f=parts(reply);
      if(f.size()!=4 || f[0]!="ATTEST" || f[1]!="healthy" || f[2]!="LAB_OK") return false;
      const auto expect=net::hmac_sha256_hex(lab_key,challenge+"|"+f[1]+"|"+f[2]);
      return net::constant_time_equal(expect,f[3]);
    } catch(const std::exception&) { return false; }
  }
  std::string handle(const std::string& line) {
    const auto fields=parts(line);
    if(fields.size()==1 && fields[0]=="PING") return "PONG";
    if(fields.size()==1 && fields[0]=="HELLO") {
      if(!check_agent(net::random_hex(16))) { log("BLOCK","AGENT_NOT_HEALTHY","-"); return "BLOCK|AGENT_NOT_HEALTHY"; }
      const auto id=net::random_hex(12);
      const auto nonce=net::random_hex(16);
      const auto secret=net::random_hex(32);
      sessions.emplace(id,Session{nonce,secret,1,Clock::now()});
      log("SESSION","CREATED",id);
      return "SESSION|"+id+"|"+nonce+"|"+secret;
    }
    if(fields.size()==6 && fields[0]=="BEAT") {
      const auto& id=fields[1];
      const auto found=sessions.find(id);
      if(found==sessions.end()) { log("BLOCK","UNKNOWN_SESSION",id); return "BLOCK|UNKNOWN_SESSION"; }
      auto& s=found->second;
      if(Clock::now()-s.last_heartbeat>std::chrono::milliseconds(ttl_ms)) {
        sessions.erase(found); log("BLOCK","HEARTBEAT_TIMEOUT",id); return "BLOCK|HEARTBEAT_TIMEOUT";
      }
      const auto mac=net::hmac_sha256_hex(s.secret,id+"|"+fields[2]+"|"+fields[3]+"|"+fields[4]);
      if(!net::constant_time_equal(mac,fields[5])) { log("BLOCK","MAC_INVALID",id); return "BLOCK|MAC_INVALID"; }
      if(fields[3]!=s.nonce) { log("BLOCK","NONCE_MISMATCH",id); return "BLOCK|NONCE_MISMATCH"; }
      uint64_t seq=0;
      try { seq=parse_sequence(fields[2]); }
      catch(const std::exception&) { log("BLOCK","BAD_SEQUENCE",id); return "BLOCK|BAD_SEQUENCE"; }
      if(seq!=s.next_sequence) { log("BLOCK","REPLAY_OR_SEQUENCE_GAP",id); return "BLOCK|REPLAY_OR_SEQUENCE_GAP"; }
      if(fields[4]!="healthy") { log("BLOCK","CLIENT_INTEGRITY_MISMATCH",id); return "BLOCK|CLIENT_INTEGRITY_MISMATCH"; }
      if(!check_agent(net::random_hex(16))) { log("BLOCK","AGENT_NOT_HEALTHY",id); return "BLOCK|AGENT_NOT_HEALTHY"; }
      ++s.next_sequence;
      s.nonce=net::random_hex(16);
      s.last_heartbeat=Clock::now();
      log("ALLOW","HEARTBEAT_ACCEPTED",id);
      return "ALLOW|"+std::to_string(seq)+"|"+s.nonce;
    }
    log("BLOCK","INVALID_FRAME","-");
    return "BLOCK|INVALID_FRAME";
  }
};
}
int main(int argc, char** argv) {
  try {
    net::Runtime runtime;
    const auto port=net::parse_port(net::get_arg(argc,argv,"--port","48391"));
    Gateway gateway{};
    gateway.agent_port=net::parse_port(net::get_arg(argc,argv,"--agent-port","48392"));
    gateway.lab_key=net::get_arg(argc,argv,"--lab-key","LAB_SHARED_ATTEST_KEY");
    const auto ttl_str=net::get_arg(argc,argv,"--ttl-ms","1500");
    gateway.ttl_ms=std::stoi(ttl_str);
    if(gateway.ttl_ms<100 || gateway.ttl_ms>60000) throw std::runtime_error("ttl-ms must be 100..60000");
    const auto audit_path=net::get_arg(argc,argv,"--audit", "");
    if(!audit_path.empty()) {
      gateway.audit.open(audit_path,std::ios::app);
      if(!gateway.audit) throw std::runtime_error("cannot open audit file");
    }
    auto listener=net::listen_loopback(port);
    std::cout << "GATEWAY_READY port=" << port << " agent_port=" << gateway.agent_port << std::endl;
    while(true) {
      auto peer=net::accept_one(listener);
      try {
        const auto msg=net::read_line(peer);
        net::send_line(peer,gateway.handle(msg));
      } catch(const std::exception& e) {
        gateway.log("NETWORK_ERROR",net::sanitize(e.what()),"-");
        try { net::send_line(peer,"BLOCK|NETWORK_ERROR"); } catch(...) {}
      }
    }
  } catch(const std::exception& e) { std::cerr << "gateway fatal=" << e.what() << '\n'; return 1; }
}
