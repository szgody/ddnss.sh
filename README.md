<p align="left">
  English | <a href="README_CN.md">中文</a>
</p>

<div align="center">
  <h1>A DDNS Shell script: ddnss.sh</h1>
</div>

<p align="center">
  <a href="https://github.com/qingzi-zhang/ddnss.sh/blob/main/LICENSE">
    <img alt="Apache License Version 2.0" src="https://img.shields.io/github/license/qingzi-zhang/ddnss.sh">
  </a>
</p>

- A dynamic DNS via DNSPod client written purely in shell (Unix shell) language.
- Bourne Again Shell, Dropbear SSH, Bourne Shell and POSIX compatible.
- Simple and very easy to use.

## Supported DDNS Services

|Status |API Version|DDNS Services
|:-----:|:---------:|----------------
|✅     |V3         |Tencent DNSPod

# Installation
## Required to install cURL and OpenSSL
- ***Debian***
```
sudo apt update
sudo apt install curl openssl
```
- ***OpenWrt***
```
opkg update
opkg install curl openssl-util
```

## Clone & Setup
```
git clone https://github.com/qingzi-zhang/ddns.sh
ddnss_home="${HOME}/.ddnss.sh"
mkdir -p "${ddnss_home}"
mkdir -p -m 0700 "/var/log/ddnss/"
cp ddnss.sh/config/ddnss.conf "${ddnss_home}/ddnss.conf"
cp ddnss.sh/scripts/ddnss.sh "${ddnss_home}"
chmod 0700 "${ddnss_home}/ddnss.sh"
echo 'alias ddnss.sh="'${ddnss_home}/ddnss.sh'"' > "${ddnss_home}/ddnss.sh.env"
source "${ddnss_home}/ddnss.sh.env"
```
> [!NOTE]
> Optional - Add to profile: _`source $HOME/.ddnss.sh/ddnss.sh.env`_

# Configuration
Edit the DDNS configuration in the file: **`$HOME/.ddnss.sh/ddnss.conf`**
> [!NOTE]
> Optional - Log_File: The log file should be located in the /var/log/ directory and have write permissions
- Log_File=`/var/log/ddnss/ddnss.log`
- Tencent_SecretId=`AKIDz8krbsJ5yKBZQpn74WFkmLPx3*******`
- Tencent_SecretKey=`Gu5t9xGARNpq86cd98joQYCN3*******`
> [!TIP]
> Format: `DDNS=domain fullname,ip_version,interface,eui64_suffix`
- DDNS=`ai.ddns-shell.com,IPv6,br-lan,07e2:00c:0012:aaaa`

# Usage
```
Usage:
  ddnss.sh [options]

Options:
  -h, --help           Print this help message
  --config=<file>      Read config from a file
  --force-update       Proceed with the update regardless of IP status
  --log-level=<0|1>    Set the log level to 0 or 1 (0: Error, 1: Verbose)
```

# A DDNS Shell script
## Mini flowchart
![diagram](svg/Main.svg)
## Configuration flowchart
![diagram](svg/parse_opt.svg)
## Process records flowchart
![diagram](svg/proc_ddns_rec.svg)