#!/usr/bin/env python3
"""
Advanced TCP port scanner (Scapy)

to prove:
    sudo python3 port_scanner.py 10.12.0.10 -p 20-1024,8080 \ -m syn,ack -t 200 --banner
"""
import argparse
import random
import socket
import sys
import threading
import time
from queue import Queue

from scapy.all import IP, TCP, sr1, conf

conf.verb = 0  # Silence Scapy’s default output

RESULTS  = {}  # {port: 'open' | 'closed' | 'filtered'}
BANNERS  = {}  # {port: banner string}
LOCK     = threading.Lock()


def parse_ports(ports_arg: str):
    #Convert a string like 22,80,1000‑1100 into a sorted list of ints
    ports = set()
    for part in ports_arg.split(','):
        if '-' in part:
            start, end = part.split('-')
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def banner_grab(ip: str, port: int, timeout: float = 2) -> str:
    #Try to pull a service banner via plain TCP
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        banner = sock.recv(1024).decode(errors='ignore').strip()
        sock.close()
        return banner
    except Exception:
        return ''


def send_receive(pkt, timeout):
    #Wrapper around sr1 that ignores unreachable hosts
    try:
        return sr1(pkt, timeout=timeout)
    except PermissionError:
        sys.exit("[-] Root privileges required for raw‑socket modes")
    except Exception:
        return None


def scan_worker(ip, mode, timeout, grab_banner, queue: Queue):
    #Thread worker: takes ports from queue and scans them
    while True:
        try:
            port = queue.get_nowait()
        except Exception:
            return

        result = 'filtered'  # Default until proven otherwise

        if mode == 'connect':
            # Full TCP connect() scan (no raw sockets required)
            try:
                sock = socket.create_connection((ip, port), timeout=timeout)
                sock.close()
                result = 'open'
                if grab_banner:
                    BANNERS[port] = banner_grab(ip, port)
            except (socket.timeout, ConnectionRefusedError):
                result = 'closed'
            except OSError:
                pass  # Filtered / unreachable

        else:
            # Raw‑socket scans (SYN, FIN, NULL, XMAS, ACK)
            flags_map = {
                'syn':  'S',
                'fin':  'F',
                'null': '',
                'xmas': 'FPU',
                'ack':  'A'
            }
            tcp_flags = flags_map[mode]
            src_port  = random.randint(1024, 65535)

            probe = IP(dst=ip) / TCP(sport=src_port,
                                     dport=port,
                                     flags=tcp_flags)
            resp = send_receive(probe, timeout)

            if resp is None:
                result = 'filtered'

            elif resp.haslayer(TCP):
                tcp = resp.getlayer(TCP)

                if mode == 'syn':
                    if tcp.flags == 0x12:          # SYN‑ACK ⇒ open
                        result = 'open'
                        # Send RST to avoid completing handshake
                        send_receive(IP(dst=ip) /
                                     TCP(sport=src_port,
                                         dport=port,
                                         flags='R'), timeout=0.1)
                    elif tcp.flags == 0x14:        # RST‑ACK ⇒ closed
                        result = 'closed'

                elif mode == 'ack':
                    # ACK scan only differentiates filtered/unfiltered
                    result = 'unfiltered' if tcp.flags & 0x04 else 'filtered'

                else:  # FIN / NULL / XMAS scans
                    # RFC 793: closed ports reply RST
                    result = 'closed' if tcp.flags & 0x14 else 'open|filtered'

            elif resp.haslayer('ICMP'):
                icmp = resp.getlayer('ICMP')
                if int(icmp.type) == 3 and int(icmp.code) in (1, 2, 3, 9, 10, 13):
                    result = 'filtered'

        with LOCK:
            RESULTS.setdefault(port, result)

        queue.task_done()


def main():
    parser = argparse.ArgumentParser(description="Scapy multi‑mode port scanner")
    parser.add_argument('target_ip')
    parser.add_argument('-p', '--ports', default='1-1024',
                        help='Comma list or ranges, e.g. 22,80,8000-8100')
    parser.add_argument('-m', '--mode', default='syn',
                        choices=['syn', 'connect', 'fin', 'null', 'xmas', 'ack'],
                        help='Scan type')
    parser.add_argument('-t', '--threads', type=int, default=100,
                        help='Concurrent worker threads')
    parser.add_argument('--timeout', type=float, default=1.0,
                        help='Timeout per port (seconds)')
    parser.add_argument('--banner', action='store_true',
                        help='Attempt banner‑grab (connect scan only)')
    args = parser.parse_args()

    # prepare work queue
    ports = parse_ports(args.ports)
    q = Queue()
    for p in ports:
        q.put(p)

    print(f"[+] Scanning {args.target_ip} ({len(ports)} ports)  "
          f"mode={args.mode}…")
    start = time.time()

    # launch workers
    workers = [threading.Thread(target=scan_worker,
                                args=(args.target_ip, args.mode, args.timeout,
                                      args.banner, q),
                                daemon=True)
               for _ in range(args.threads)]
    for w in workers:
        w.start()

    # to wwait until queue is empty
    q.join()
    elapsed = time.time() - start

    #  tidy 
    open_ports = sorted(p for p, status in RESULTS.items() if status.startswith('open'))
    print(f"\nScan completed in {elapsed:.2f} s")
    if open_ports:
        print("Open ports:", ', '.join(map(str, open_ports)))
        if args.banner and BANNERS:
            for p, b in BANNERS.items():
                print(f"  {p}: {b}")
    else:
        print("No open ports detected.")

    closed = sum(1 for s in RESULTS.values() if s == 'closed')
    filtered = len(ports) - len(open_ports) - closed
    print(f"Summary → open: {len(open_ports)}   closed: {closed}   "
          f"filtered: {filtered}")


if __name__ == '__main__':
    main()
