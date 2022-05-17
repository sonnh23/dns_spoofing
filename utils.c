#include "utils.h"
#include "dnsspoof.h"
int compare_mac(uint8_t* mac_1, uint8_t* mac_2){
    int i;
    for(i = 0; i< ETH_ALEN; i++)
        if(*(mac_1+i) != *(mac_2+i))
            return 0;
    return 1;
}
int compare_ip(uint8_t* ip_1, uint8_t* ip_2){
    int i;
    for(i = 0; i< 4; i++)
        if(*(ip_1+i) != *(ip_2+i))
            return 0;
    return 1;
}

void dns_pac_status(uint8_t* pac, char* qname, uint16_t qtype, uint16_t qclass){
    int i;
    uint8_t* dns_data = (uint8_t*) (pac + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dnshdr));
    struct ether_header *eth_hdr = (struct ether_header*) pac;
    struct iphdr *ip_hdr = (struct iphdr*) (pac + sizeof(struct ether_header));
    struct udphdr *udp_hdr = (struct udphdr*) (pac + sizeof(struct ether_header) + sizeof(struct iphdr));
    struct dnshdr* dns_hdr = (struct dnshdr*) (pac + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) );
    struct dnsquery* dns_query = (struct dnsquery*) (pac + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dnshdr));
    fprintf(stderr, "\n____________________________________\n");
    fprintf(stderr, "ether_dhost: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x ", *eth_hdr->ether_dhost, *(eth_hdr->ether_dhost+1), *(eth_hdr->ether_dhost+2), *(eth_hdr->ether_dhost+3), *(eth_hdr->ether_dhost+4), *(eth_hdr->ether_dhost+5));
    fprintf(stderr, "| ether_shost: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x ", *eth_hdr->ether_shost, *(eth_hdr->ether_shost+1), *(eth_hdr->ether_shost+2), *(eth_hdr->ether_shost+3), *(eth_hdr->ether_shost+4), *(eth_hdr->ether_shost+5));
    fprintf(stderr, "| ether_type: 0x%.4x\n", ntohs(eth_hdr->ether_type));

    fprintf(stderr, "ver: %d | ihl: %d", ntohs(ip_hdr->version), ntohs(ip_hdr->ihl));
    fprintf(stderr, " | tos: 0x%.2x", ip_hdr->tos);
    fprintf(stderr, " | tot_len: 0x%.4x", ntohs(ip_hdr->tot_len));
    fprintf(stderr, " | id: 0x%4x", ntohs(ip_hdr->id));
    fprintf(stderr, " | frag_off: 0x%.4x", ntohs(ip_hdr->frag_off));
    fprintf(stderr, " | ttl: 0x%2x", ip_hdr->ttl);
    fprintf(stderr, " | protocol: 0x%.2x", ip_hdr->protocol);
    fprintf(stderr, " | check: 0x%.4x", ntohs( ip_hdr->protocol));
    fprintf(stderr, " | saddr: %d.%d.%d.%d", *ip_hdr->saddr, *(ip_hdr->saddr+1), *(ip_hdr->saddr+2), *(ip_hdr->saddr+3));
    fprintf(stderr, " | daddr: %d.%d.%d.%d\n", *ip_hdr->daddr, *(ip_hdr->daddr+1), *(ip_hdr->daddr+2), *(ip_hdr->daddr+3));

    fprintf(stderr, "sport: 0x%.4x", ntohs(udp_hdr->uh_sport));
    fprintf(stderr, " | dport: 0x%.4x", ntohs(udp_hdr->uh_dport));
    fprintf(stderr, " | len: 0x%.4x", ntohs(udp_hdr->len));
    fprintf(stderr, " | check: 0x%.4x\n", ntohs(udp_hdr->check));

    fprintf(stderr, "tid: 0x%.4x", ntohs(dns_hdr->tid));
    fprintf(stderr, " | flags: 0x%.4x", ntohs(dns_hdr->flags));
    fprintf(stderr, " | questions: %d", ntohs(dns_hdr->questitons));
    fprintf(stderr, " | answer RRs: %d", dns_hdr->answer_rrs);
    fprintf(stderr, " | authority RRs: %d", dns_hdr->auth_rrs);
    fprintf(stderr, " | add RRs: %d\n", dns_hdr->add_rrs);

    fprintf(stderr, "qname: %s", qname);
    fprintf(stderr, " | type: 0x%.4x", qtype);
    fprintf(stderr, " | class:0x %.4x\n", qclass);
    fprintf(stderr, "____________________________________\n\n");

}