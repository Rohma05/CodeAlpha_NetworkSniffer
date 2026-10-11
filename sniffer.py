#!/usr/bin/env python3
"""
CodeAlpha Cyber Security Internship - Task 1: Basic Network Sniffer

Captures network packets with scapy and shows, for each packet:
  * source / destination address (and ports)
  * the protocol (TCP, UDP, ICMP, ARP, DNS, HTTP, HTTPS, ...)
  * size, TCP flags, TTL
  * a readable preview of the payload

At the end it prints a traffic summary and can save the capture as a
.pcap file (open it in Wireshark) and a .csv file (open it in Excel).

Use it ONLY on networks you own or have permission to monitor.
"""

import argparse
import csv
import ctypes
import os
import signal
import sys
import time
from collections import Counter
from datetime import datetime

try:
    from scapy.all import (
        ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Raw, IPv6,
        conf, sniff, wrpcap,
    )
except ImportError:
    print("scapy is not installed.  Run:  pip install scapy")
    sys.exit(1)

# ----------------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------------

WELL_KNOWN_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
    995: "POP3S", 1900: "SSDP", 3389: "RDP", 5353: "mDNS",
}

# Protocols that send data WITHOUT encryption (worth flagging in a security tool)
CLEARTEXT = {"HTTP", "FTP", "FTP-DATA", "TELNET", "SMTP", "POP3", "IMAP"}

HTTP_STARTS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"HTTP/")

COLORS = {
    "TCP": "\033[36m", "UDP": "\033[34m", "ICMP": "\033[35m", "ARP": "\033[33m",
    "DNS": "\033[32m", "HTTP": "\033[91m", "HTTPS": "\033[92m",
}
RESET = "\033[0m"
DIM = "\033[90m"
BOLD = "\033[1m"
WARN = "\033[93m"


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

def is_admin():
    """True if running with the privileges needed to sniff."""
    try:
        if os.name == "nt":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def printable(data, limit):
    """Payload bytes as text, non-printable bytes replaced with dots."""
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data[:limit])


def hexdump(data, limit):
    """Classic 16-bytes-per-row hex dump."""
    chunk = data[:limit]
    rows = []
    for i in range(0, len(chunk), 16):
        row = chunk[i:i + 16]
        hx = " ".join(f"{b:02x}" for b in row)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        rows.append(f"{i:04x}  {hx:<47}  {asc}")
    return rows


def classify(pkt):
    """Return (transport, label) e.g. ('TCP', 'HTTPS') or ('UDP', 'DNS')."""
    if pkt.haslayer(ARP):
        return "ARP", "ARP"

    if pkt.haslayer(TCP):
        layer = pkt[TCP]
        transport = "TCP"
        app = WELL_KNOWN_PORTS.get(layer.dport) or WELL_KNOWN_PORTS.get(layer.sport)
    elif pkt.haslayer(UDP):
        layer = pkt[UDP]
        transport = "UDP"
        app = WELL_KNOWN_PORTS.get(layer.dport) or WELL_KNOWN_PORTS.get(layer.sport)
    elif pkt.haslayer(ICMP):
        return "ICMP", "ICMP"
    elif pkt.haslayer(IPv6):
        return "IPv6", "IPv6"
    elif pkt.haslayer(IP):
        return "IP", "IP"
    else:
        return "Other", "Other"

    if pkt.haslayer(DNS):
        app = "DNS"
    return transport, (app or transport)


def addresses(pkt):
    """Return (src, dst, sport, dport) for the packet."""
    sport = dport = None
    if pkt.haslayer(IP):
        src, dst = pkt[IP].src, pkt[IP].dst
    elif pkt.haslayer(IPv6):
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
    elif pkt.haslayer(ARP):
        src, dst = pkt[ARP].psrc, pkt[ARP].pdst
    elif hasattr(pkt, "src") and hasattr(pkt, "dst"):
        src, dst = pkt.src, pkt.dst  # MAC addresses
    else:
        src = dst = "?"

    if pkt.haslayer(TCP):
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
    elif pkt.haslayer(UDP):
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
    return src, dst, sport, dport


def extra_info(pkt, payload):
    """A short human-readable note about what this packet is doing."""
    if pkt.haslayer(ARP):
        a = pkt[ARP]
        if a.op == 1:
            return f"Who has {a.pdst}? Tell {a.psrc}"
        if a.op == 2:
            return f"{a.psrc} is at {a.hwsrc}"
        return f"ARP op {a.op}"

    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        try:
            name = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
        except Exception:
            name = "?"
        kind = "response" if pkt[DNS].qr == 1 else "query"
        return f"DNS {kind}: {name}"

    if pkt.haslayer(ICMP):
        icmp_types = {0: "Echo reply (ping)", 3: "Destination unreachable",
                      8: "Echo request (ping)", 11: "Time exceeded"}
        t = pkt[ICMP].type
        return icmp_types.get(t, f"ICMP type {t}")

    if payload and payload.startswith(HTTP_STARTS):
        line = payload.split(b"\r\n", 1)[0].decode(errors="replace")
        return line[:100]

    return ""


# ----------------------------------------------------------------------------
# Sniffer
# ----------------------------------------------------------------------------

class Sniffer:
    def __init__(self, args):
        self.args = args
        self.count = 0
        self.total_bytes = 0
        self.start = time.time()
        self.proto_counter = Counter()
        self.src_counter = Counter()
        self.dst_counter = Counter()
        self.conversations = Counter()
        self.cleartext_seen = Counter()
        self.saved_packets = []
        self.csv_file = None
        self.csv_writer = None
        self.use_color = not args.no_color
        self.wanted = (
            {p.strip().lower() for p in args.proto.split(",") if p.strip()}
            if args.proto else None
        )

        if args.output:
            self.csv_file = open(args.output + ".csv", "w", newline="", encoding="utf-8")
            self.csv_writer = csv.writer(self.csv_file)
            self.csv_writer.writerow(
                ["no", "time", "transport", "protocol", "src", "sport",
                 "dst", "dport", "length", "flags", "ttl", "info"]
            )

    # -- filtering --------------------------------------------------------

    def accept(self, pkt):
        """Friendly protocol filter (--proto tcp,dns,...). No BPF needed."""
        if self.wanted is None:
            return True
        transport, label = classify(pkt)
        return transport.lower() in self.wanted or label.lower() in self.wanted

    # -- per packet -------------------------------------------------------

    def handle(self, pkt):
        self.count += 1
        length = len(pkt)
        self.total_bytes += length

        transport, label = classify(pkt)
        src, dst, sport, dport = addresses(pkt)
        flags = str(pkt[TCP].flags) if pkt.haslayer(TCP) else ""
        ttl = pkt[IP].ttl if pkt.haslayer(IP) else (pkt[IPv6].hlim if pkt.haslayer(IPv6) else "")
        payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
        info = extra_info(pkt, payload)

        # statistics
        self.proto_counter[label] += 1
        self.src_counter[src] += 1
        self.dst_counter[dst] += 1
        self.conversations[(src, dst)] += 1
        if label in CLEARTEXT:
            self.cleartext_seen[label] += 1

        if self.args.output:
            self.saved_packets.append(pkt)
            self.csv_writer.writerow([
                self.count,
                datetime.fromtimestamp(float(pkt.time)).isoformat(timespec="milliseconds"),
                transport, label, src, sport or "", dst, dport or "",
                length, flags, ttl, info,
            ])

        self.print_packet(pkt, transport, label, src, dst, sport, dport,
                          length, flags, ttl, payload, info)

    def paint(self, text, label):
        if not self.use_color:
            return text
        return f"{COLORS.get(label, '')}{text}{RESET}"

    def print_packet(self, pkt, transport, label, src, dst, sport, dport,
                     length, flags, ttl, payload, info):
        ts = datetime.fromtimestamp(float(pkt.time)).strftime("%H:%M:%S.%f")[:-3]
        proto = label if label == transport else f"{transport}/{label}"
        left = f"{src}:{sport}" if sport is not None else str(src)
        right = f"{dst}:{dport}" if dport is not None else str(dst)
        warn = "!" if label in CLEARTEXT else " "
        warn_txt = f"{WARN}{warn}{RESET}" if self.use_color else warn

        line = (f"#{self.count:<5} {ts}  {self.paint(f'{proto:<11}', label)} "
                f"{left} -> {right}  len={length}")
        if flags:
            line += f"  flags={flags}"
        if ttl != "":
            line += f"  ttl={ttl}"
        print(f"{warn_txt}{line}")

        if info:
            print(f"        {DIM if self.use_color else ''}info   : {info}"
                  f"{RESET if self.use_color else ''}")

        if self.args.verbose:
            print(f"        layers : {pkt.summary()}")

        if payload and self.args.payload_bytes > 0:
            if self.args.hex:
                print("        payload:")
                for row in hexdump(payload, self.args.payload_bytes):
                    print(f"          {row}")
            else:
                text = printable(payload, self.args.payload_bytes)
                more = "..." if len(payload) > self.args.payload_bytes else ""
                print(f"        payload: ({len(payload)} bytes) {text}{more}")

    # -- summary ----------------------------------------------------------

    def close(self):
        if self.csv_file:
            self.csv_file.close()

    def summary(self):
        elapsed = max(time.time() - self.start, 0.001)
        bold = BOLD if self.use_color else ""
        reset = RESET if self.use_color else ""
        line = "=" * 64

        print(f"\n{line}\n{bold} CAPTURE SUMMARY{reset}\n{line}")
        print(f" Packets captured : {self.count}")
        print(f" Total data       : {self.total_bytes:,} bytes "
              f"({self.total_bytes / 1024:.1f} KB)")
        print(f" Duration         : {elapsed:.1f} s  "
              f"({self.count / elapsed:.1f} packets/s)")

        if self.count == 0:
            print("\n No packets were captured. Check the interface, the filter,")
            print(" and make sure there is traffic (open a website, run a ping).")
            print(line)
            return

        print(f"\n{bold} Protocols{reset}")
        biggest = self.proto_counter.most_common(1)[0][1]
        for proto, n in self.proto_counter.most_common():
            bar = "#" * max(1, int(30 * n / biggest))
            pct = 100 * n / self.count
            print(f"   {proto:<10} {n:>6}  {pct:5.1f}%  {bar}")

        print(f"\n{bold} Top sources{reset}")
        for ip, n in self.src_counter.most_common(5):
            print(f"   {ip:<40} {n:>6} packets")

        print(f"\n{bold} Top destinations{reset}")
        for ip, n in self.dst_counter.most_common(5):
            print(f"   {ip:<40} {n:>6} packets")

        print(f"\n{bold} Busiest conversations{reset}")
        for (s, d), n in self.conversations.most_common(5):
            print(f"   {s} -> {d}   ({n} packets)")

        if self.cleartext_seen:
            names = ", ".join(f"{k} ({v})" for k, v in self.cleartext_seen.items())
            warn = WARN if self.use_color else ""
            print(f"\n{warn} [!] Unencrypted protocols seen: {names}{reset}")
            print("     Data sent over these can be read by anyone on the network.")
            print("     Prefer HTTPS, SSH and other encrypted alternatives.")

        print(line)

    def save_pcap(self):
        if self.args.output and self.saved_packets:
            path = self.args.output + ".pcap"
            wrpcap(path, self.saved_packets)
            print(f" Saved {len(self.saved_packets)} packets to {path} "
                  f"(open in Wireshark)")
            print(f" Saved packet table to {self.args.output}.csv")


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        description="CodeAlpha Basic Network Sniffer - capture and analyse packets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python sniffer.py --list-interfaces
  python sniffer.py -c 50                       capture 50 packets
  python sniffer.py -t 30 -o capture            capture 30 s, save capture.pcap/.csv
  python sniffer.py --proto dns,http -c 20      only DNS and HTTP packets
  python sniffer.py -f "tcp port 80" --hex      BPF filter + hex payload dump
  python sniffer.py -r capture.pcap             analyse a saved capture offline
""",
    )
    p.add_argument("-i", "--iface", help="network interface (see --list-interfaces)")
    p.add_argument("-c", "--count", type=int, default=0,
                   help="stop after N packets (default: run until Ctrl+C)")
    p.add_argument("-t", "--timeout", type=int, default=None,
                   help="stop after N seconds")
    p.add_argument("-f", "--filter", help='BPF filter, e.g. "tcp port 80"')
    p.add_argument("--proto",
                   help="friendly filter, comma separated: tcp,udp,icmp,arp,dns,http,https")
    p.add_argument("-r", "--read", metavar="PCAP",
                   help="read packets from a .pcap file instead of the network")
    p.add_argument("-o", "--output", metavar="NAME",
                   help="save capture as NAME.pcap and NAME.csv")
    p.add_argument("-p", "--payload-bytes", type=int, default=64,
                   help="payload bytes to preview (default 64, 0 = hide)")
    p.add_argument("--hex", action="store_true", help="show payload as a hex dump")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="also show the layer stack of each packet")
    p.add_argument("--no-color", action="store_true", help="disable coloured output")
    p.add_argument("--list-interfaces", action="store_true",
                   help="list network interfaces and exit")
    return p


def banner(args, source):
    print("=" * 64)
    print(" CodeAlpha Basic Network Sniffer")
    print("=" * 64)
    print(f" Source    : {source}")
    print(f" Filter    : {args.filter or 'none'}   Protocols: {args.proto or 'all'}")
    limit = []
    if args.count:
        limit.append(f"{args.count} packets")
    if args.timeout:
        limit.append(f"{args.timeout} s")
    print(f" Stops at  : {' or '.join(limit) if limit else 'Ctrl+C'}")
    print(" '!' marks unencrypted protocols.  Press Ctrl+C to stop.")
    print("=" * 64)


def main():
    # Make Unicode-safe output and enable ANSI colours on Windows terminals
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    if os.name == "nt":
        os.system("")

    args = build_parser().parse_args()

    if args.list_interfaces:
        print(conf.ifaces)
        return 0

    live = not args.read
    if live and not is_admin():
        print("[!] Not running as Administrator/root. Live capture will probably fail.")
        print("    Windows: open VS Code or PowerShell with 'Run as administrator'.")
        print("    Linux/macOS: use sudo.\n")

    source = args.read if args.read else (args.iface or f"default ({conf.iface})")
    banner(args, source)

    sniffer = Sniffer(args)

    # Make Ctrl+C stop capture cleanly on every platform
    signal.signal(signal.SIGINT, signal.default_int_handler)

    try:
        kwargs = dict(
            prn=sniffer.handle,
            lfilter=sniffer.accept,
            store=False,
        )
        if args.count:
            kwargs["count"] = args.count
        if args.read:
            kwargs["offline"] = args.read
        else:
            if args.iface:
                kwargs["iface"] = args.iface
            if args.timeout:
                kwargs["timeout"] = args.timeout
            if args.filter:
                kwargs["filter"] = args.filter
        sniff(**kwargs)
    except KeyboardInterrupt:
        print("\n[*] Capture stopped by user.")
    except PermissionError:
        print("\n[!] Permission denied. Run the terminal as Administrator (or use sudo).")
        return 1
    except FileNotFoundError:
        print(f"\n[!] File not found: {args.read}")
        return 1
    except Exception as exc:  # noqa: BLE001 - give friendly hints for common setup issues
        print(f"\n[!] Capture failed: {exc}")
        print("    Common fixes on Windows:")
        print("      1. Install Npcap from https://npcap.com (tick 'WinPcap API-compatible mode')")
        print("      2. Run the terminal as Administrator")
        print("      3. Pick another interface with --list-interfaces and -i")
        return 1
    finally:
        sniffer.close()

    sniffer.summary()
    sniffer.save_pcap()
    return 0


if __name__ == "__main__":
    sys.exit(main())
