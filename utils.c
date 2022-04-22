#include "utils.h"

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