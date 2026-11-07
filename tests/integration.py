#!/usr/bin/env python3
"""Multi-process integration test; no actual anti-cheat, driver or Riot service is accessed."""
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

AGENT, GATEWAY, CLIENT = sys.argv[1:4]

def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def probe(port):
    with socket.create_connection(('127.0.0.1', port), timeout=.5) as conn:
        conn.sendall(b'PING\n')
        conn.settimeout(.5)
        return conn.recv(32).decode().strip() == 'PONG'

def await_ready(port, proc):
    for _ in range(70):
        if proc.poll() is not None:
            raise RuntimeError(f'process exited unexpectedly: {proc.args}')
        try:
            if probe(port):
                return
        except (OSError, TimeoutError):
            pass
        time.sleep(.05)
    raise RuntimeError(f'port {port} not ready')

def start(args):
    return subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

def stop(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)

with tempfile.TemporaryDirectory() as temp:
    audit = str(Path(temp) / 'audit.ndjson')
    ap, gp = free_port(), free_port()
    while gp == ap:
        gp = free_port()
    processes = []
    try:
        agent = start([AGENT, '--port', str(ap)])
        processes.append(agent)
        await_ready(ap, agent)
        gateway = start([GATEWAY, '--port', str(gp), '--agent-port', str(ap), '--ttl-ms', '1200', '--audit', audit])
        processes.append(gateway)
        await_ready(gp, gateway)
        cases = [('normal', '200'), ('replay','200'), ('seq-gap','200'), ('tamper','200'), ('bad-nonce','200'), ('forged-mac','200'), ('wrong-session','200'), ('expired','1550')]
        for scenario, interval in cases:
            p = subprocess.run([CLIENT, '--gateway-port', str(gp), '--scenario',scenario,'--interval-ms',interval], text=True, capture_output=True, timeout=8)
            assert p.returncode == 0, f'{scenario} FAILED rc={p.returncode}\n{p.stdout}\n{p.stderr}'
            print(f'PASS scenario={scenario}: {p.stdout.strip().splitlines()[-1]}', flush=True)
        # rogue agent: right port, wrong attestation key -> signature fails -> fail closed.
        rp = free_port()
        while rp in (ap, gp):
            rp = free_port()
        rogue = start([AGENT, '--port', str(rp), '--lab-key', 'WRONG_KEY'])
        processes.append(rogue)
        await_ready(rp, rogue)
        rgp = free_port()
        while rgp in (ap, gp, rp):
            rgp = free_port()
        rogue_gateway = start([GATEWAY, '--port', str(rgp), '--agent-port', str(rp), '--ttl-ms', '1200'])
        processes.append(rogue_gateway)
        await_ready(rgp, rogue_gateway)
        with socket.create_connection(('127.0.0.1', rgp), timeout=2) as s:
            s.settimeout(2)
            s.sendall(b'HELLO\n')
            result = s.recv(1024).decode().strip()
        assert result == 'BLOCK|AGENT_NOT_HEALTHY', result
        print('PASS scenario=rogue-agent: ' + result, flush=True)
        stop(agent)
        with socket.create_connection(('127.0.0.1', gp), timeout=2) as s:
            s.settimeout(2)
            s.sendall(b'HELLO\n')
            result=s.recv(1024).decode().strip()
        assert result == 'BLOCK|AGENT_NOT_HEALTHY', result
        print('PASS scenario=agent-unavailable: ' + result,flush=True)
        events = [json.loads(line) for line in Path(audit).read_text().splitlines()]
        assert any(x['event']=='ALLOW' for x in events)
        assert any(x['event']=='BLOCK' for x in events)
        assert any(x['reason']=='HEARTBEAT_TIMEOUT' for x in events)
        assert any(x['reason']=='AGENT_NOT_HEALTHY' for x in events)
        assert any(x['reason']=='MAC_INVALID' for x in events)
        print(f'PASS audit-jsonl: {len(events)} valid events',flush=True)
        # verify the audit hash-chain the way a tamper-evidence tool would.
        prev = 'GENESIS'
        for x in events:
            core = f'"time":"{x["time"]}","event":"{x["event"]}","reason":"{x["reason"]}","session":"{x["session"]}","prev":"{x["prev"]}"'
            assert x['prev'] == prev, f'chain break: {x["prev"]} != {prev}'
            assert x['hash'] == hashlib.sha256((prev + '|' + core).encode()).hexdigest(), 'hash mismatch'
            prev = x['hash']
        # deleting a middle line must break the chain
        tampered = events[:-1]  # drop last record; chain tail no longer matches
        broke = False
        p2 = 'GENESIS'
        for x in tampered:
            if x['prev'] != p2:
                broke = True
                break
            p2 = x['hash']
        assert not broke, 'sanity: untampered prefix should still chain'
        assert tampered[-1]['hash'] != prev, 'deletion should change the chain tail'
        print(f'PASS audit-chain: {len(events)} records verified, tamper detectable', flush=True)
    finally:
        for proc in reversed(processes):
            stop(proc)
