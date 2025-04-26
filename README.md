# 🔍 Static IP Gateway Scanner

A Python-based utility that scans local network subnets to identify responsive gateways using static IP assignment. Ideal for troubleshooting, testing router configurations, and network automation on macOS, Linux, or Raspberry Pi.

## 🚀 Features

- Set static IP and ping gateways to check availability.
- Supports full subnet scans or pattern-based scans (e.g., `192.168.*.*`).
- Scan only `.1` suffix hosts using `--known-host`.
- Customize gateway suffixes, DNS, and skipped gateways.
- Works on **macOS** and **Linux** (including Raspberry Pi).
- Logs successful hits to a file.

## ⚙️ Requirements

- Python 3.6+
- `nmcli` (for Linux/RPi network management)
- `networksetup` (macOS)
- `sudo` privileges required on Linux/macOS

## 📦 Installation

Clone the repo:

```bash
git clone https://github.com/mikesaraus/ping-host.git
cd ping-host

sudo python3 ping-host.py
```

### 🔧 Command Line Options

| Argument             | Type     | Default                          | Description                                                        |
| -------------------- | -------- | -------------------------------- | ------------------------------------------------------------------ |
| `--ssid`             | string   | `None`                           | (Linux/RPi only) WiFi SSID to connect and set IP                   |
| `--dns`              | string   | `8.8.8.8`                        | DNS server address to use                                          |
| `--resume-from`      | string   | `None`                           | Resume scanning after this IP                                      |
| `--log-file`         | string   | `found_gateways.log`             | Log file to store successful gateway responses                     |
| `--static-ip-suffix` | int      | `99`                             | The last octet used when assigning a static IP                     |
| `--gateway-suffixes` | JSON str | `[1, 254, 100, 10, 2]`           | List of gateway suffixes to try                                    |
| `--skip-gateways`    | JSON str | `["192.168.0.1", "192.168.1.1"]` | Gateways to skip (useful for avoiding duplicates or known devices) |
| `--hosts`            | string   | `None`                           | Subnet pattern to scan (e.g. `192.168.*.*`, `172.16.10.*`)         |
| `--known-host`       | flag     | `False`                          | Restrict gateway suffixes to only `.1` (use with `--hosts`)        |
| `--ping-sec`         | int      | `2`                              | Timeout duration (in seconds) for ping attempts                    |
