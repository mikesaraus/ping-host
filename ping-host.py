import subprocess
import logging
import time
import argparse
import ipaddress
import sys
import os
import platform
import json

def is_root():
    return os.geteuid() == 0

def run_cmd(cmd):
    try:
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

def ping_gateway(gateway):
    return run_cmd(f"ping -c 1 -W 1 {gateway}")

def set_static_ip(ip, gateway, ssid=None, dns=None, os_type="Linux"):
    if os_type == "Darwin":
        cmd = f'networksetup -setmanual "Wi-Fi" {ip} 255.255.255.0 {gateway}'
    else:
        cmd = f'nmcli con modify "{ssid}" ipv4.method manual ipv4.addresses {ip}/24 ipv4.gateway {gateway} ipv4.dns "{dns}"'
    return run_cmd(cmd)

def reconnect(ssid=None):
    return run_cmd(f'nmcli con down "{ssid}" && nmcli con up "{ssid}"')

def ip_to_int(ip):
    return int(ipaddress.IPv4Address(ip))

def expand_host_pattern(pattern):
    octets = pattern.split('.')
    ranges = []
    for octet in octets:
        if octet == '*':
            ranges.append(range(0, 256))
        else:
            ranges.append([int(octet)])
    return ranges

def try_subnet(base_ip, resume_from=None, ssid=None, dns=None, os_type="Linux", static_suffix=99, gateway_suffixes=None, skip_gateways=None, auto_stop=True):
    for gw_suffix in gateway_suffixes:
        gateway = f"{base_ip}.{gw_suffix}"

        if gateway in skip_gateways:
            print(f"⏭️ Skipping known gateway: {gateway}")
            continue

        if resume_from and ip_to_int(gateway) <= ip_to_int(resume_from):
            print(f"⏩ Skipping {gateway} (before resume point)")
            continue

        static_ip = f"{base_ip}.{static_suffix}"
        print(f"🔄 Trying gateway: {gateway} with IP {static_ip}")
        if set_static_ip(static_ip, gateway, ssid, dns, os_type):
            go_connect = True
            if os_type != "Darwin" and not reconnect(ssid):
                go_connect = False
            if go_connect:
                time.sleep(2)
                if ping_gateway(gateway):
                    logging.info(f"✅ Gateway {gateway} responded (IP used: {static_ip})")
                    print(f"✅ Success: {gateway} is alive (IP used: {static_ip})")
                    if auto_stop:
                        return True
    return False

def scan_pattern(args, os_type):
    resume_from = args.resume_from
    ssid = args.ssid
    dns = args.dns
    static_suffix = args.static_ip_suffix
    gateway_suffixes = json.loads(args.gateway_suffixes)
    skip_gateways = set(json.loads(args.skip_gateways))
    auto_stop = args.auto_stop

    if args.known_host:
        gateway_suffixes = [1]

    if args.hosts:
        host_ranges = expand_host_pattern(args.hosts)
        for a in host_ranges[0]:
            for b in host_ranges[1]:
                for c in host_ranges[2]:
                    base_ip = f"{a}.{b}.{c}"
                    if try_subnet(base_ip, resume_from, ssid, dns, os_type, static_suffix, gateway_suffixes, skip_gateways, auto_stop):
                        return
    else:
        # Default full scan
        for third in range(0, 256):
            base_ip = f"192.168.{third}"
            if try_subnet(base_ip, resume_from, ssid, dns, os_type, static_suffix, gateway_suffixes, skip_gateways, auto_stop):
                return
        for second in range(16, 32):
            for third in range(0, 256):
                base_ip = f"172.{second}.{third}"
                if try_subnet(base_ip, resume_from, ssid, dns, os_type, static_suffix, gateway_suffixes, skip_gateways, auto_stop):
                    return
        for second in range(0, 256):
            for third in range(0, 256):
                base_ip = f"10.{second}.{third}"
                if try_subnet(base_ip, resume_from, ssid, dns, os_type, static_suffix, gateway_suffixes, skip_gateways, auto_stop):
                    return

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Static IP Gateway Scanner")
    parser.add_argument("--resume-from", help="IP address to resume scanning from (exclusive)", default=None)
    parser.add_argument("--ssid", help="WiFi SSID name (required for Linux/RPi)", default=None)
    parser.add_argument("--dns", help="DNS server to use", default='8.8.8.8')
    parser.add_argument("--log-file", help="Path to log file", default="found_gateways.log")
    parser.add_argument("--static-ip-suffix", type=int, help="Static IP suffix to use", default=99)
    parser.add_argument("--gateway-suffixes", help="List of gateway suffixes (as JSON)", default="[1, 254, 100, 10, 2]")
    parser.add_argument("--skip-gateways", help="List of gateways to skip (as JSON)", default='["192.168.0.1", "192.168.1.1"]')
    parser.add_argument("--auto-stop", help="Scan only known host suffixes (.1)", default=False)
    parser.add_argument("--hosts", help="Subnet pattern to scan (e.g., 192.168.*.*)", default='192.168.*.*')
    parser.add_argument("--known-host", help="Scan only known host suffixes (.1)", action="store_true")
    args = parser.parse_args()

    os_type = platform.system()
    if os_type in ("Darwin", "Linux") and not is_root():
        print("🚫 This script must be run with sudo/root privileges.")
        sys.exit(1)

    logging.basicConfig(filename=args.log_file, level=logging.INFO, format='%(asctime)s - %(message)s')

    try:
        scan_pattern(args, os_type)
    except KeyboardInterrupt:
        print("⛔ Stopped by user.")
