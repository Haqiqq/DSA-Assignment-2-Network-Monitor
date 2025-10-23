
 /* Compile:
 *   g++ -std=c++17 packet.cpp -o pac
 * Run:
 *   sudo ./network_monitor <interface> <filter_src_IP> <filter_dst_IP>
 *
 * Example:
 *   sudo ./packet eth0 192.168.1.10 192.168.1.20
 *
 * TO RUN, AFTER COMPILING, run this example line to test
 */

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>       
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>       
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <net/if.h>



using namespace std;

// constraints here
const int MAX_PACKET_SIZE = 65536;
const int ETH_MTU = 1500;
const int REPLAY_RETRIES = 2;
const int SKIP_OVERSIZED_THRESHOLD = 10;
const int DEMO_DURATION_SECONDS = 60;

// all helpers
static string nowStr() {
    time_t t = time(nullptr);
    char buf[64];
    struct tm *tm_info = localtime(&t);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_info);
    return string(buf);
}

static string ipToStr(uint32_t ip_netorder) {
    struct in_addr a;
    a.s_addr = ip_netorder;
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return string(buf);
}

static string ipv6ToStr(const struct in6_addr &addr6) {
    char buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &addr6, buf, sizeof(buf));
    return string(buf);
}

static bool isValidIP(const string &ip) {
    struct in_addr sa;
    struct in6_addr sa6;
    if (inet_pton(AF_INET, ip.c_str(), &sa) == 1) return true;
    if (inet_pton(AF_INET6, ip.c_str(), &sa6) == 1) return true;
    return false;
}

/*  stack (linked list) stores layer names */
struct LayerNode {
    char *layer; 
    LayerNode *next;
};

struct LayerStack {
    LayerNode *top;
    LayerStack() : top(nullptr) {}
    ~LayerStack() {
        while (top) { pop(); }
    }

    bool push_cstr(const char *s) {
        LayerNode *n = (LayerNode*)malloc(sizeof(LayerNode));
        if (!n) return false;
        size_t len = strlen(s) + 1;
        n->layer = (char*)malloc(len);
        if (!n->layer) { free(n); return false; }
        memcpy(n->layer, s, len);
        n->next = top;
        top = n;
        return true;
    }

    // pop returns a heap string, caller must free()
    char* pop() {
        if (!top) return nullptr;
        LayerNode *n = top;
        top = n->next;
        char *out = n->layer;
        free(n);
        return out;
    }

    bool isEmpty() const { return top == nullptr; }
};

// Packet struct
struct Packet {
    unsigned long long id;
    char timestamp[64];
    int size;
    unsigned char data[MAX_PACKET_SIZE];
    int retry_count;

    // parsed
    bool is_ipv4;
    bool is_ipv6;
    char srcIP[INET6_ADDRSTRLEN];
    char dstIP[INET6_ADDRSTRLEN];
    unsigned short srcPort;
    unsigned short dstPort;
    char proto[16];

    Packet() {
        id = 0;
        timestamp[0] = '\0';
        size = 0;
        retry_count = 0;
        is_ipv4 = false;
        is_ipv6 = false;
        srcIP[0] = '\0';
        dstIP[0] = '\0';
        srcPort = 0;
        dstPort = 0;
        proto[0] = '\0';
        memset(data, 0, sizeof(data));
    }
};

// queue (linked list) for packets
struct PacketNode {
    Packet pkt;
    PacketNode *next;
};

struct PacketQueue {
    PacketNode *head;
    PacketNode *tail;
    int count;

    PacketQueue() : head(nullptr), tail(nullptr), count(0) {}

    ~PacketQueue() {
        while (head) {
            PacketNode *n = head;
            head = head->next;
            free(n);
        }
    }

    bool enqueue(const Packet &p) {
        PacketNode *n = (PacketNode*)malloc(sizeof(PacketNode));
        if (!n) return false;
        n->pkt = p; // struct copy, copies fixed arrays
        n->next = nullptr;
        if (!tail) {
            head = tail = n;
        } else {
            tail->next = n;
            tail = n;
        }
        ++count;
        return true;
    }

    // dequeue returns true if success, false if empty
    bool dequeue(Packet &out) {
        if (!head) return false;
        PacketNode *n = head;
        out = n->pkt;
        head = n->next;
        if (!head) tail = nullptr;
        free(n);
        --count;
        return true;
    }

    bool isEmpty() const { return head == nullptr; }
    int size() const { return count; }
};

//counters
unsigned long long globalPacketID = 1;
int oversizedSkipped = 0;
int oversizedTotal = 0;
unsigned long long capturedCount = 0;
unsigned long long dissectedCount = 0;
unsigned long long filteredCount = 0;
unsigned long long replayedCount = 0;


PacketQueue replayQueue;
PacketQueue backupQueue;

//network helpers 
int getInterfaceIndex(int sockfd, const string &ifname) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) return -1;
    return ifr.ifr_ifindex;
}

bool getInterfaceMAC(int sockfd, const string &ifname, unsigned char mac_out[6]) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) return false;
    memcpy(mac_out, ifr.ifr_hwaddr.sa_data, 6);
    return true;
}

//dissection code
void dissectPacket(Packet &p) {
    LayerStack ls;
    ls.push_cstr("Ethernet");

    if (p.size < (int)sizeof(struct ethhdr)) {
        printf("[%s] Packet %llu too small for Ethernet\n", nowStr().c_str(), p.id);
        return;
    }

    struct ethhdr *eth = (struct ethhdr*)p.data;
    uint16_t eth_type = ntohs(eth->h_proto);

    size_t offset = sizeof(struct ethhdr);

    if (eth_type == ETH_P_IP) {
        ls.push_cstr("IPv4");
        if (p.size >= (int)(offset + sizeof(struct iphdr))) {
            struct iphdr *iph = (struct iphdr*)(p.data + offset);
            p.is_ipv4 = true;
            string s = ipToStr(iph->saddr);
            string d = ipToStr(iph->daddr);
            strncpy(p.srcIP, s.c_str(), sizeof(p.srcIP)-1);
            strncpy(p.dstIP, d.c_str(), sizeof(p.dstIP)-1);
            int iphdrlen = iph->ihl * 4;
            offset += iphdrlen;

            if (iph->protocol == IPPROTO_TCP) {
                ls.push_cstr("TCP");
                strncpy(p.proto, "TCP", sizeof(p.proto)-1);
                if (p.size >= (int)(offset + sizeof(struct tcphdr))) {
                    struct tcphdr *tcph = (struct tcphdr*)(p.data + offset);
                    p.srcPort = ntohs(tcph->source);
                    p.dstPort = ntohs(tcph->dest);
                }
            } else if (iph->protocol == IPPROTO_UDP) {
                ls.push_cstr("UDP");
                strncpy(p.proto, "UDP", sizeof(p.proto)-1);
                if (p.size >= (int)(offset + sizeof(struct udphdr))) {
                    struct udphdr *udph = (struct udphdr*)(p.data + offset);
                    p.srcPort = ntohs(udph->source);
                    p.dstPort = ntohs(udph->dest);
                }
            } else {
                strncpy(p.proto, "Other", sizeof(p.proto)-1);
            }
        } else {
            printf("[%s] Packet %llu malformed IPv4\n", nowStr().c_str(), p.id);
        }
    } else if (eth_type == ETH_P_IPV6) {
        ls.push_cstr("IPv6");
        if (p.size >= (int)(offset + sizeof(struct ip6_hdr))) {
            struct ip6_hdr *ip6h = (struct ip6_hdr*)(p.data + offset);
            p.is_ipv6 = true;
            string s = ipv6ToStr(ip6h->ip6_src);
            string d = ipv6ToStr(ip6h->ip6_dst);
            strncpy(p.srcIP, s.c_str(), sizeof(p.srcIP)-1);
            strncpy(p.dstIP, d.c_str(), sizeof(p.dstIP)-1);
            offset += sizeof(struct ip6_hdr);

            uint8_t nxt = ip6h->ip6_nxt;
            if (nxt == IPPROTO_TCP) {
                ls.push_cstr("TCP");
                strncpy(p.proto, "TCP", sizeof(p.proto)-1);
                if (p.size >= (int)(offset + sizeof(struct tcphdr))) {
                    struct tcphdr *tcph = (struct tcphdr*)(p.data + offset);
                    p.srcPort = ntohs(tcph->source);
                    p.dstPort = ntohs(tcph->dest);
                }
            } else if (nxt == IPPROTO_UDP) {
                ls.push_cstr("UDP");
                strncpy(p.proto, "UDP", sizeof(p.proto)-1);
                if (p.size >= (int)(offset + sizeof(struct udphdr))) {
                    struct udphdr *udph = (struct udphdr*)(p.data + offset);
                    p.srcPort = ntohs(udph->source);
                    p.dstPort = ntohs(udph->dest);
                }
            } else {
                strncpy(p.proto, "Other", sizeof(p.proto)-1);
            }
        } else {
            printf("[%s] Packet %llu malformed IPv6\n", nowStr().c_str(), p.id);
        }
    } else {
        strncpy(p.proto, "Non-IP", sizeof(p.proto)-1);
    }

    // print dissection summary
    printf("[%s] === Dissect packet #%llu ===\n", nowStr().c_str(), p.id);
    printf("    ts: %s\n", p.timestamp);
    printf("    size: %d\n", p.size);
    printf("    Layers (top->bottom):\n");
    // pop and print
    int idx = 0;
    while (!ls.isEmpty()) {
        char *layer = ls.pop();
        if (!layer) break;
        printf("      %d: %s\n", ++idx, layer);
        free(layer);
    }
    if (p.is_ipv4 || p.is_ipv6) {
        printf("    %s -> %s (%s)\n", p.srcIP, p.dstIP, p.proto);
        if (p.srcPort || p.dstPort) {
            printf("    ports: %u -> %u\n", p.srcPort, p.dstPort);
        }
    }
    printf("\n");

    ++dissectedCount;
}

//filter check 
string filter_src_ip;
string filter_dst_ip;

bool packetMatchesFilter(const Packet &p) {
    if ((p.is_ipv4 || p.is_ipv6) && p.srcIP[0] && p.dstIP[0]) {
        if (filter_src_ip == string(p.srcIP) && filter_dst_ip == string(p.dstIP)) return true;
    }
    return false;
}

//replay logic 

bool attemptReplay(int send_sock, struct sockaddr_ll *device, Packet &p) {
    for (int attempt = 0; attempt <= REPLAY_RETRIES; ++attempt) {
        ssize_t sent = sendto(send_sock, p.data, p.size, 0, (struct sockaddr*)device, sizeof(*device));
        if (sent == p.size) {
            printf("[%s] SUCCESS: replayed packet #%llu (attempt %d/%d)\n",
                   nowStr().c_str(), p.id, attempt+1, REPLAY_RETRIES+1);
            ++replayedCount;
            return true;
        } else {
            fprintf(stderr, "[%s] FAIL: replay attempt %d/%d for packet #%llu (errno=%d)\n",
                    nowStr().c_str(), attempt+1, REPLAY_RETRIES+1, p.id, errno);
            // small pause between retries
            usleep(100 * 1000); // 100 ms
        }
    }
    // all attempts failed
    return false;
}

// main sequential flow 

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: sudo %s <interface> <filter_src_IP> <filter_dst_IP>\n", argv[0]);
        return 1;
    }

    string ifname = argv[1];
    filter_src_ip = string(argv[2]);
    filter_dst_ip = string(argv[3]);

    if (!isValidIP(filter_src_ip) || !isValidIP(filter_dst_ip)) {
        fprintf(stderr, "Error: invalid filter IP(s)\n");
        return 1;
    }

    printf("\n\n");
    printf("  PACKETS CAPTURING \n");
    printf("  Interface: %s\n", ifname.c_str());
    printf("  Filter:    %s -> %s\n", filter_src_ip.c_str(), filter_dst_ip.c_str());
    printf("  Demo time: %d seconds\n", DEMO_DURATION_SECONDS);
    printf("\n\n");

    // open raw socket for capture
    int rawsock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (rawsock < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    int ifindex = getInterfaceIndex(rawsock, ifname);
    if (ifindex < 0) {
        fprintf(stderr, "Error: cannot get index for interface %s\n", ifname.c_str());
        close(rawsock);
        return 1;
    }
    sll.sll_ifindex = ifindex;

    if (bind(rawsock, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(rawsock);
        return 1;
    }

    // Set recv timeout so we can end after DEMO_DURATION_SECONDS 
    struct timeval tv;
    tv.tv_sec = 1; // 1 second timeout for recvfrom
    tv.tv_usec = 0;
    setsockopt(rawsock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    printf("[%s] starting capture on %s ...\n", nowStr().c_str(), ifname.c_str());

    time_t start_time = time(nullptr);
    unsigned char buffer[MAX_PACKET_SIZE];

    // capture loop: run ~DEMO_DURATION_SECONDS and process each packet sequentially
    while (difftime(time(nullptr), start_time) < DEMO_DURATION_SECONDS) {
        ssize_t data_size = recvfrom(rawsock, buffer, MAX_PACKET_SIZE, 0, nullptr, nullptr);
        if (data_size < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // timeout, just continue to check demo duration
                continue;
            } else {
                perror("recvfrom");
                continue;
            }
        }

        // build Packet
        Packet p;
        p.id = globalPacketID++;
        string ts = nowStr();
        strncpy(p.timestamp, ts.c_str(), sizeof(p.timestamp)-1);
        p.size = (int)data_size;
        if (p.size > MAX_PACKET_SIZE) p.size = MAX_PACKET_SIZE;
        memcpy(p.data, buffer, p.size);

        ++capturedCount;

        // oversized handling
        if (p.size > ETH_MTU) {
            ++oversizedTotal;
            if (oversizedSkipped >= SKIP_OVERSIZED_THRESHOLD) {
                printf("[%s] skipping oversized packet #%llu size=%d (threshold exceeded)\n",
                       nowStr().c_str(), p.id, p.size);
                continue;
            } else {
                ++oversizedSkipped;
                printf("[%s] warning oversized packet #%llu size=%d (skipped count %d)\n",
                       nowStr().c_str(), p.id, p.size, oversizedSkipped);
                // continue processing (we still parse and maybe enqueue)
            }
        }

        printf("[%s] captured packet #%llu size=%d\n", nowStr().c_str(), p.id, p.size);

        // dissect
        dissectPacket(p);

        // filter: check src/dst IPs
        if (packetMatchesFilter(p)) {
            double delay_ms = ((double)p.size) / 1000.0;
            printf("[%s] MATCH: packet #%llu %s -> %s (%s), est delay %.2f ms\n",
                   nowStr().c_str(), p.id, p.srcIP, p.dstIP, p.proto, delay_ms);
            ++filteredCount;

            // add to replay queue (we'll try replay after capture loop)
            if (!replayQueue.enqueue(p)) {
                fprintf(stderr, "[%s] replay queue enqueue failed for pkt %llu; putting to backup\n",
                        nowStr().c_str(), p.id);
                backupQueue.enqueue(p);
            }
        }

    } // end capture loop

    printf("\n[%s] capture period ended. Now processing replay queue...\n", nowStr().c_str());

    // prepare send socket for replay
    int send_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (send_sock < 0) {
        perror("replay socket");
        // still print final report using current counters
    } else {
        int send_ifindex = getInterfaceIndex(send_sock, ifname);
        if (send_ifindex < 0) {
            fprintf(stderr, "Error: cannot get index for interface %s (replay)\n", ifname.c_str());
            close(send_sock);
            send_sock = -1;
        } else {
            // device address for sendto
            struct sockaddr_ll device;
            memset(&device, 0, sizeof(device));
            device.sll_family = AF_PACKET;
            device.sll_ifindex = send_ifindex;
            device.sll_halen = ETH_ALEN;
            device.sll_protocol = htons(ETH_P_ALL);

            // get interface MAC 
            unsigned char if_mac[6];
            if (!getInterfaceMAC(send_sock, ifname, if_mac)) {
                fprintf(stderr, "Warning: could not get interface MAC for %s\n", ifname.c_str());
            }

            // replay loop, dequeue each from replayQueue and attempt send
            Packet rp;
            while (replayQueue.dequeue(rp)) {
                // try to extract destination MAC from the original packet
                if (rp.size >= (int)sizeof(struct ethhdr)) {
                    struct ethhdr *eth = (struct ethhdr*)rp.data;
                    memcpy(device.sll_addr, eth->h_dest, ETH_ALEN);
                } else {
                    // fallback: send to broadcast
                    device.sll_addr[0] = 0xff;
                    device.sll_addr[1] = 0xff;
                    device.sll_addr[2] = 0xff;
                    device.sll_addr[3] = 0xff;
                    device.sll_addr[4] = 0xff;
                    device.sll_addr[5] = 0xff;
                }

                bool ok = attemptReplay(send_sock, &device, rp);
                if (!ok) {
                    rp.retry_count = REPLAY_RETRIES + 1;
                    printf("[%s] moving pkt #%llu to backup after failed replay\n", nowStr().c_str(), rp.id);
                    backupQueue.enqueue(rp);
                }
            } // end replayQueue processing
        } // end ifindex ok
    } // end send_sock ok

    // At this point, we attempted replay for matched packets.
    // We can optionally try to replay backupQueue entries once more, or just report them.

    // Print backup status and try a single extra attempt for backups (optional)
    if (!backupQueue.isEmpty() && send_sock >= 0) {
        printf("\n[%s] Attempting single recovery attempts for backup queue (%d packets)...\n",
               nowStr().c_str(), backupQueue.size());
        Packet bp;
        int backup_attempts = 0;
        while (backupQueue.dequeue(bp)) {
            ++backup_attempts;
            struct sockaddr_ll device;
            memset(&device, 0, sizeof(device));
            device.sll_family = AF_PACKET;
            device.sll_ifindex = ifindex;
            device.sll_halen = ETH_ALEN;
            if (bp.size >= (int)sizeof(struct ethhdr)) {
                struct ethhdr *eth = (struct ethhdr*)bp.data;
                memcpy(device.sll_addr, eth->h_dest, ETH_ALEN);
            } else {
                memset(device.sll_addr, 0xff, ETH_ALEN);
            }
            // one-shot attempt
            ssize_t sent = sendto(send_sock, bp.data, bp.size, 0, (struct sockaddr*)&device, sizeof(device));
            if (sent == bp.size) {
                printf("[%s] RECOVERED: backup pkt #%llu sent successfully\n", nowStr().c_str(), bp.id);
                ++replayedCount;
            } else {
                fprintf(stderr, "[%s] RECOVERY FAIL: backup pkt #%llu (errno=%d). Dropping.\n",
                        nowStr().c_str(), bp.id, errno);
                // in a full system, we could re-enqueue or store to disk
            }
        }
    }

    if (send_sock >= 0) close(send_sock);
    close(rawsock);

    // Final report
    printf("\nNoww, all the packet capturing report.\n");
    printf("  NETWORK MONITOR - FINAL REPORT\n");
    printf("\n");
    printf(" Total Packets Captured:    %llu\n", capturedCount);
    printf(" Total Packets Dissected:   %llu\n", dissectedCount);
    printf(" Total Packets Filtered:    %llu\n", filteredCount);
    printf(" Total Packets Replayed:    %llu\n", replayedCount);
    printf(" Oversized Packets (Total): %d\n", oversizedTotal);
    printf(" Oversized Packets (Skipped): %d\n", oversizedSkipped);
    printf(" Backup Queue Final Size:   %d\n", backupQueue.size());
    

    return 0;
}
