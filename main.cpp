// SYN Port Scanner
// This is a multi-threaded SYN port scanner. It uses raw sockets to blast SYNs and see what answers.
#include <iostream>          // For printing stuff
#include <vector>            // Vectors are just dynamic arrays
#include <thread>            // Threads, so it's not super slow
#include <atomic>            // For safe counters between threads
#include <chrono>            // Timing and sleeping
#include <mutex>             // Locking so output isn't a mess
#include <csignal>           // Catch Ctrl+C so you can bail out
#include <cstring>           // For memset, memcpy, etc.
#include <cstdlib>           // atoi, rand, etc.
#include <unistd.h>          // For close(), usleep(), etc.
#include <fcntl.h>           // Set sockets non-blocking
#include <poll.h>            // Wait for stuff to happen on sockets
#include <netinet/ip.h>      // IP header structs
#include <netinet/tcp.h>     // TCP header structs
#include <netinet/ip_icmp.h> // ICMP header structs
#include <arpa/inet.h>       // IP address helpers
#include <sys/socket.h>      // Sockets
#include <sys/types.h>       // System types
#include <sys/time.h>        // For time stuff
#include <ifaddrs.h>         // Get your own IP
#include <random>            // Random numbers
#include <algorithm>         // For shuffling

#define MAX_PORTS 65536 // All the ports (1-65535)
#define MAX_THREADS 256 // Don't go too wild with threads
#define MAX_DECOYS 8    // Max decoy IPs you can use

// What happened to a port after we scanned it
enum State : uint8_t
{
    UNK = 0,     // No clue, nothing came back
    OPEN = 1,    // Got SYN/ACK, so it's open
    CLOSED = 2,  // Got RST, so it's closed
    FILTERED = 3 // ICMP unreachable or just dropped (Firewall, etc.)
};

// Holds the result for each port
struct Result
{
    State state;
    uint8_t reason;
    Result() : state(UNK), reason(0) {}
};

// Each thread gets a chunk of ports to scan
struct Job
{
    int start, end;
};

// These keep track of what's left and make sure threads don't step on each other
std::atomic<int> live;           // How many ports are left to check
std::atomic<bool> running(true); // Is the scan still going?
std::mutex out_mutex;            // Don't let threads spam the output at once

// Checks if an IP is private, loopback, or just not for us
bool is_reserved_ip(uint32_t ip)
{
    uint32_t net = ntohl(ip);
    return (net >= 0x0A000000 && net <= 0x0AFFFFFF) || // 10.0.0.0/8 (private)
           (net >= 0x7F000000 && net <= 0x7FFFFFFF) || // 127.0.0.0/8 (loopback)
           (net >= 0xA9FE0000 && net <= 0xA9FEFFFF) || // 169.254.0.0/16 (link-local)
           (net >= 0xAC100000 && net <= 0xAC1FFFFF) || // 172.16.0.0/12 (private)
           (net >= 0xC0A80000 && net <= 0xC0A8FFFF) || // 192.168.0.0/16 (private)
           (net == 0x00000000) ||                      // 0.0.0.0 (unspecified)
           (net >= 0xE0000000);                        // 224.0.0.0+ (multicast/reserved)
}
// Standard IP/TCP checksum function, nothing fancy
unsigned short csum(unsigned short *p, int l)
{
    unsigned long sum = 0;
    while (l > 1)
    {
        sum += *p++;
        l -= 2;
    }
    if (l)
        sum += *(unsigned char *)p;
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
}

// Used for TCP checksum math, don't mess with it unless you know what you're doing
struct pseudo
{
    uint32_t src, dst;
    uint8_t zero;
    uint8_t proto;
    uint16_t len;
};

// Tries to get your local IP (not 127.x.x.x), so packets go out right
in_addr_t get_local_ip(in_addr_t dst)
{
    struct ifaddrs *ifaddr, *ifa;
    in_addr_t res = 0;
    if (getifaddrs(&ifaddr) == -1)
        return 0;
    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next)
    {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
            continue;
        struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
        // Don't use loopback
        if ((sa->sin_addr.s_addr & 0xFF) != 127)
            res = sa->sin_addr.s_addr;
    }
    freeifaddrs(ifaddr);
    return res;
}

// Gives you a random public IP (for decoys), skips all the private ones
in_addr_t rand_ip()
{
    static thread_local std::mt19937 prng(std::random_device{}());
    while (true)
    {
        uint32_t ip = prng();
        if (!is_reserved_ip(htonl(ip)))
            return htonl(ip);
    }
}

// Makes a socket non-blocking so threads don't get stuck
void set_nonblock(int fd)
{
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
}

// Each thread gets its own random number generator (no fighting)
thread_local std::mt19937 prng(std::random_device{}());
void send_syn_packets(
    int raw, in_addr_t src, in_addr_t dst, const Job &job, sockaddr_in sin,
    std::atomic<bool> &running, bool use_frag, int decoys, int pps, uint16_t sport_base)
{
    std::vector<int> ports;
    for (int p = job.start; p <= job.end; ++p)
        ports.push_back(p);
    std::shuffle(ports.begin(), ports.end(), prng);

    std::uniform_int_distribution<uint16_t> sdist(1025, 65530);
    std::uniform_int_distribution<int> ttldist(32, 255);
    std::uniform_int_distribution<int> wdist(8192, 65535);
    std::uniform_int_distribution<int> tosdist(0, 1);
    std::uniform_int_distribution<int> urgdist(0, 1);
    std::uniform_int_distribution<int> fragdist(0, 2);
    std::uniform_int_distribution<int> sleepdist(0, 150);

    int sent = 0;
    auto last = std::chrono::steady_clock::now();

    for (int port : ports)
    {
        if (!running.load())
            break;
        for (int d = 0; d <= decoys; ++d)
        {
            in_addr_t send_src = (d == 0) ? src : rand_ip();
            unsigned short sport = sport_base + (sdist(prng) % 4000);
            unsigned char pkt[64] = {0};
            iphdr *iph = (iphdr *)pkt;
            tcphdr *tcph = (tcphdr *)(pkt + sizeof(iphdr));
            iph->ihl = 5;
            iph->version = 4;
            iph->tos = tosdist(prng) ? 0 : 0x10;
            iph->tot_len = htons(sizeof(iphdr) + sizeof(tcphdr));
            iph->id = htons((unsigned short)(prng()));
            iph->frag_off = (use_frag && fragdist(prng) == 1) ? htons(0x2000) : 0;
            iph->ttl = ttldist(prng);
            iph->protocol = IPPROTO_TCP;
            iph->saddr = send_src;
            iph->daddr = dst;
            iph->check = 0;
            tcph->source = htons(sport);
            tcph->dest = htons(port);
            tcph->seq = htonl(prng());
            tcph->doff = 5;
            tcph->syn = 1;
            tcph->window = htons(wdist(prng));
            tcph->urg = urgdist(prng);
            tcph->ack = 0;
            tcph->psh = 0;
            tcph->rst = 0;
            tcph->fin = 0;
            tcph->check = 0;
            pseudo ph;
            ph.src = iph->saddr;
            ph.dst = iph->daddr;
            ph.zero = 0;
            ph.proto = IPPROTO_TCP;
            ph.len = htons(sizeof(tcphdr));
            unsigned char pseudo_pkt[sizeof(pseudo) + sizeof(tcphdr)];
            memcpy(pseudo_pkt, &ph, sizeof(pseudo));
            memcpy(pseudo_pkt + sizeof(pseudo), tcph, sizeof(tcphdr));
            tcph->check = csum((unsigned short *)pseudo_pkt, sizeof(pseudo_pkt));
            iph->check = csum((unsigned short *)iph, sizeof(iphdr));
            int r = sendto(raw, pkt, sizeof(iphdr) + sizeof(tcphdr), MSG_DONTWAIT, (sockaddr *)&sin, sizeof(sin));
            if (r < 0 && (errno == EAGAIN || errno == ENOBUFS))
                usleep(120); // burst backoff
        }
        sent++;
        if (pps > 0 && sent % pps == 0)
        {
            auto now = std::chrono::steady_clock::now();
            auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(now - last).count();
            if (diff < 1000)
                usleep(1000 * (1000 - diff) / pps);
            last = std::chrono::steady_clock::now();
        }
        else
        {
            usleep(pps > 0 ? 0 : 30 + sleepdist(prng));
        }
    }
}

void sigint_handler(int)
{
    running.store(false);
    std::lock_guard<std::mutex> lock(out_mutex);
    std::cout << "\nScan aborted.\n";
}

void recv_responses(
    int raw, int icmp, in_addr_t dst, int p1, int p2, std::vector<Result> &results,
    std::atomic<bool> &running, int scan_total, std::vector<uint16_t> &valid_sports)
{
    unsigned char buf[2048];
    struct pollfd pfds[2] = {{raw, POLLIN, 0}, {icmp, POLLIN, 0}};
    int tmo = 4900;
    while (tmo > 0 && live > 0 && running.load())
    {
        int n = poll(pfds, 2, 10);
        if (n <= 0)
        {
            tmo--;
            continue;
        }
        if (pfds[0].revents & POLLIN)
        {
            int len = recv(raw, buf, sizeof(buf), 0);
            if (len < 0)
                continue;
            iphdr *iph = (iphdr *)buf;
            if (iph->protocol != IPPROTO_TCP)
                continue;
            tcphdr *tcph = (tcphdr *)(buf + iph->ihl * 4);
            int p = ntohs(tcph->source);
            uint16_t sport = ntohs(tcph->dest);
            if (iph->saddr != dst || p < p1 || p > p2)
                continue;
            if (std::find(valid_sports.begin(), valid_sports.end(), sport) == valid_sports.end())
                continue;
            if (results[p].state)
                continue;
            if (tcph->syn && tcph->ack)
            {
                results[p].state = OPEN;
                results[p].reason = 1;
            }
            else if (tcph->rst)
            {
                results[p].state = CLOSED;
                results[p].reason = 2;
            }
            live--;
        }
        if (pfds[1].revents & POLLIN)
        {
            int len = recv(icmp, buf, sizeof(buf), 0);
            if (len < 0)
                continue;
            iphdr *iph = (iphdr *)buf;
            if (iph->protocol != IPPROTO_ICMP)
                continue;
            icmphdr *icmph = (icmphdr *)(buf + iph->ihl * 4);
            if (icmph->type == 3)
            {
                iphdr *i2 = (iphdr *)(buf + iph->ihl * 4 + sizeof(icmphdr));
                tcphdr *t2 = (tcphdr *)((unsigned char *)i2 + i2->ihl * 4);
                int p = ntohs(t2->dest);
                uint16_t sport = ntohs(t2->source);
                if (i2->daddr != dst || p < p1 || p > p2)
                    continue;
                if (std::find(valid_sports.begin(), valid_sports.end(), sport) == valid_sports.end())
                    continue;
                if (results[p].state)
                    continue;
                results[p].state = FILTERED;
                results[p].reason = icmph->code;
                live--;
            }
        }
    }
}

int main(int ac, char **av)
{
    if (ac < 4)
    {
        std::cout << "Usage: " << av[0]
                  << " <target_ip> <start_port> <end_port> [threads:1-256] [decoys:0-8] [fragment:0/1] [pps]\n";
        std::cout << "Example: sudo ./synscan 192.168.1.1 1 65535 128 4 1 100000\n";
        return 1;
    }
    std::signal(SIGINT, sigint_handler);

    char *target = av[1];
    int p1 = atoi(av[2]), p2 = atoi(av[3]);
    int nthreads = (ac > 4) ? atoi(av[4]) : 64;
    int decoys = (ac > 5) ? atoi(av[5]) : 4;
    bool use_frag = (ac > 6) ? atoi(av[6]) : true;
    int pps = (ac > 7) ? atoi(av[7]) : 0; // 0 = as fast as possible

    if (p1 < 1 || p2 > 65535 || p1 > p2)
    {
        std::cout << "Invalid ports.\n";
        return 1;
    }
    if (nthreads < 1)
        nthreads = 1;
    if (nthreads > MAX_THREADS)
        nthreads = MAX_THREADS;
    if (decoys < 0)
        decoys = 0;
    if (decoys > MAX_DECOYS)
        decoys = MAX_DECOYS;

    int raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    int icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (raw < 0 || icmp < 0)
    {
        perror("socket");
        return 1;
    }

    int one = 1;
    setsockopt(raw, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    set_nonblock(raw);
    set_nonblock(icmp);

    in_addr_t dst = inet_addr(target);
    in_addr_t src = get_local_ip(dst);
    if (!src)
    {
        std::cerr << "Can't get local IP\n";
        return 1;
    }

    sockaddr_in sin = {AF_INET, 0, {dst}};
    std::vector<uint16_t> sports;
    for (int t = 0; t < nthreads; ++t)
        sports.push_back(1024 + rand() % 50000);

    std::vector<Result> results(MAX_PORTS);
    int seg = (p2 - p1 + 1) / nthreads;
    live = p2 - p1 + 1;
    std::atomic<bool> runflag(true);
    auto tstart = std::chrono::steady_clock::now();

    std::vector<std::thread> threads;
    for (int i = 0; i < nthreads; ++i)
    {
        int jstart = p1 + i * seg, jend = (i == nthreads - 1 ? p2 : jstart + seg - 1);
        threads.emplace_back(send_syn_packets, raw, src, dst, Job{jstart, jend}, sin, std::ref(runflag), use_frag, decoys, pps, sports[i]);
    }

    std::thread recv_thr(recv_responses, raw, icmp, dst, p1, p2, std::ref(results), std::ref(runflag), p2 - p1 + 1, std::ref(sports));

    std::cout << "Scanning " << target << " from " << inet_ntoa(*(in_addr *)&src)
              << " ports " << p1 << "-" << p2
              << " threads=" << nthreads
              << " decoys=" << decoys
              << " fragments=" << use_frag
              << (pps ? (" pps=" + std::to_string(pps)) : " max-speed") << std::endl;

    for (auto &t : threads)
        t.join();
    runflag.store(false);
    recv_thr.join();

    auto tend = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(tend - tstart).count();

    std::lock_guard<std::mutex> lock(out_mutex);
    std::cout << "-- Results --\n";
    for (int port = p1; port <= p2; port++)
    {
        if (results[port].state == OPEN)
            std::cout << port << " OPEN\n";
        else if (results[port].state == CLOSED)
            std::cout << port << " CLOSED\n";
        else if (results[port].state == FILTERED)
            std::cout << port << " FILTERED (ICMP code " << (int)results[port].reason << ")\n";
        else
            std::cout << port << " UNK/NO RESPONSE\n";
    }
    std::cout << "Scan completed in " << elapsed << "s\n";
    close(raw);
    close(icmp);
    return 0;
}
// This took me a while to write, so please don't copy it without crediting me.
// Legal action will be taken if you do not credit me.
// Will not work on Windows, only Linux/BSD, neither will it work on WSL.
// EOF