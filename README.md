# CodeAlpha Basic Network Sniffer

A command-line packet sniffer written in Python with [scapy](https://scapy.net/).
Built for the **CodeAlpha Cyber Security Internship, Task 1**.

It captures live network traffic (or reads a saved `.pcap` file), breaks each packet
down into its layers, and shows the information that matters: source and destination
addresses, protocol, ports, size, TCP flags, and a preview of the payload. At the end it prints
a traffic summary and can save the capture for Wireshark or Excel.

> **Use responsibly.** Only capture traffic on networks you own or have written
> permission to monitor. Sniffing other people's traffic without permission is illegal.

## Features

- Live capture on any interface, or offline analysis of `.pcap` files
- Decodes **Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ARP, DNS** and recognises common
  application protocols (HTTP, HTTPS, SSH, FTP, SMTP, ...) by port
- Shows source/destination IP and port, packet length, TCP flags and TTL
- Readable **payload preview** (ASCII) or full **hex dump** (`--hex`)
- Explains what a packet is doing: DNS names being looked up, HTTP request lines,
  ARP "who has" questions, ping requests
- Flags **unencrypted protocols** (HTTP, FTP, Telnet, ...) with a `!` and a security warning
- Filters: friendly `--proto dns,tcp` and standard BPF `-f "tcp port 80"`
- Stop by packet count, time limit, or Ctrl+C
- **Capture summary**: protocol breakdown chart, top sources and destinations, busiest conversations
- Exports to `.pcap` (Wireshark) and `.csv` (Excel)
- Colour-coded output

## Setup (Windows)

1. **Install Python 3** from python.org (tick "Add Python to PATH").
2. **Install Npcap** from <https://npcap.com>. During install, tick
   **"Install Npcap in WinPcap API-compatible Mode"**. Scapy needs it to read packets from the network card.
3. Install scapy:
   ```
   pip install -r requirements.txt
   ```
4. **Run your terminal as Administrator** (right-click VS Code or PowerShell, then "Run as administrator").
   Capturing packets needs elevated privileges.

On Linux/macOS: `pip install scapy` and run with `sudo`.

## Usage

```
python sniffer.py --list-interfaces          # find your network card
python sniffer.py -c 50                      # capture 50 packets
python sniffer.py -t 30 -o capture           # capture 30 s, save capture.pcap + capture.csv
python sniffer.py --proto dns,http -c 20     # only DNS and HTTP packets
python sniffer.py -f "tcp port 80" --hex     # BPF filter and hex payload
python sniffer.py -i "Wi-Fi" -c 100          # choose an interface
python sniffer.py -r capture.pcap            # analyse a saved capture
python sniffer.py --help                     # all options
```

### Generate some traffic to look at

While the sniffer runs, in another terminal:

```
ping 8.8.8.8                       # ICMP echo request / reply
nslookup example.com               # DNS query and response
curl http://example.com            # unencrypted HTTP (shows the request line)
curl https://example.com           # HTTPS (payload is encrypted)
```

## Example output

```
================================================================
 CodeAlpha Basic Network Sniffer
================================================================
 Source    : default (Wi-Fi)
 Filter    : none   Protocols: all
 Stops at  : 20 packets
================================================================
 #1     14:03:22.481  UDP/DNS     192.168.1.5:53012 -> 192.168.1.1:53  len=74
        info   : DNS query: example.com
        payload: (32 bytes) .....example.com.....
!#2     14:03:22.530  TCP/HTTP    192.168.1.5:51234 -> 93.184.216.34:80  len=140  flags=PA  ttl=128
        info   : GET / HTTP/1.1
        payload: (86 bytes) GET / HTTP/1.1..Host: example.com..User-Agent: curl/8.0...
 #3     14:03:22.612  TCP/HTTPS   93.184.216.34:443 -> 192.168.1.5:51240  len=66  flags=A  ttl=54
```

*(Illustrative sample. Real output depends on your network.)*

## How a packet is structured

Data on a network travels inside nested "envelopes". Each layer wraps the one above it:

| Layer | What it adds | Example fields |
|-------|--------------|----------------|
| **Ethernet** (link) | Hardware addressing on the local network | Source/destination MAC address |
| **IP** (network) | Addressing across networks, routing | Source/destination IP, TTL, protocol number |
| **TCP / UDP** (transport) | Delivery between programs | Ports, TCP flags, sequence numbers |
| **Application** | The actual message | HTTP request, DNS question, TLS data |

**TCP flags** shown by the sniffer: `S` = SYN (start a connection), `A` = ACK (acknowledge),
`P` = PSH (push data), `F` = FIN (close), `R` = RST (abort). A normal connection begins with
`S`, then `SA`, then `A` (the three-way handshake).

**Why HTTPS payloads look like gibberish:** HTTPS encrypts everything above TCP using TLS,
so a sniffer sees only random-looking bytes. Plain HTTP, FTP and Telnet send text in the clear,
which is why this tool warns about them.

## Project files

| File | Purpose |
|------|---------|
| `sniffer.py` | The sniffer |
| `requirements.txt` | Python dependency (`scapy`) |
| `README.md` | This document |

## What I learned

- How data moves through layers from the network card up to the application
- How to read TCP flags and recognise a handshake
- Why encryption (HTTPS/SSH) matters, and how easily plaintext protocols can be read
- How DNS, ARP and ICMP behave on a normal network
- Using scapy to parse and filter packets, and exporting captures for Wireshark

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `Sniffing and sending packets is not available at layer 2: winpcap is not installed` | Install Npcap (WinPcap API-compatible mode) and restart the terminal |
| Permission error / no packets | Run the terminal as Administrator |
| Wrong interface, nothing captured | Use `--list-interfaces`, then `-i "<name>"` |
| `-f` BPF filter errors | Use `--proto tcp,udp,...` instead |
