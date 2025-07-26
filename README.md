# SYN Port Scanner

This is a super-fast, multi-threaded SYN port scanner I wrote in C++. It fires SYN packets using raw sockets and tells you which ports are open, closed, or just ignoring the sender. It’s got decoys, fragmentation, and you can tweak the speed and stealth however you want.

## What’s Cool About It?
- Blazing fast thanks to multi-threading
- SYN scan style (like nmap -sS)
- Decoy IPs to mess with anyone watching (So you can't be easily traced)
- Optional IP fragmentation (for those pesky firewalls)
- Tweak threads, decoys, and packets-per-second (PPS)
- Tells you if a port is OPEN, CLOSED, FILTERED, or just not talking (UNK/NO RESPONSE)

## How Do I Use It?
**You need to run this as root (sudo), or it won’t work. Raw sockets are shitty like that.**

```
sudo ./synscan <target_ip> <start_port> <end_port> [threads:1-256] [decoys:0-8] [fragment:0/1] [pps]
```

### Example Time
```
sudo ./synscan 192.168.1.1 1 1024 64 2 1 10000
```
That’ll scan ports 1-1024 on 192.168.1.1, using 64 threads, 2 decoy IPs, fragmentation on, and 10,000 packets/sec. 

### What Do All Those Args Mean?
- `<target_ip>`: Who you’re scanning (IPv4 only, like 192.168.1.1)
- `<start_port>`: Where to start (1-65535)
- `<end_port>`: Where to stop (1-65535)
- `[threads]`: How many threads to use (default: 64, max: 256)
- `[decoys]`: How many decoy IPs to throw in (default: 4, max: 8)
- `[fragment]`: Break up packets? (1 = yes, 0 = nah, default: 1)
- `[pps]`: Packets per second (0 = as fast as possible, default: 0)

## What Do the Results Mean?
- `OPEN`: Port said hi with a SYN/ACK (it’s open)
- `CLOSED`: Port slammed the door with a RST (it’s closed)
- `FILTERED`: No answer or got ICMP unreachable (firewall or blackhole)
- `UNK/NO RESPONSE`: No reply at all.

## What Do I Need?
- Linux or BSD (no Windows, no WSL, sorry)
- Root privileges (sudo is your friend)
- g++ (C++11 or newer)

## How Do I Build It?
```
g++ -std=c++11 -O2 -o synscan main.cpp -lpthread
```

## Legal Stuff & Credits
- For learning and legal/authorized security testing only!
- Don’t scan stuff you don’t own or have permission for. Seriously.
- If you use or tweak this, just give me a shout-out somewhere.

---
**Disclaimer:** I’m not responsible if you get in trouble or break something. 

**Liscense:** MIT License (see LICENSE file)
