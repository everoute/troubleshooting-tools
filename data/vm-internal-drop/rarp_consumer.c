#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <time.h>

#define BUFFER_SIZE 65536

#define ETH_P_RARP 0x8035

void print_timestamp() {
    time_t now;
    struct tm *tm_info;
    char time_string[26];
    
    time(&now);
    tm_info = localtime(&now);
    strftime(time_string, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    printf("[%s] ", time_string);
}

void print_mac(unsigned char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", 
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(unsigned char *ip) {
    printf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
}

void process_rarp_packet(unsigned char *buffer, int size) {
    struct ethhdr *eth_header = (struct ethhdr *)buffer;
    struct arphdr *arp_header = (struct arphdr *)(buffer + sizeof(struct ethhdr));
    
    print_timestamp();
    printf("RARP packet received (size: %d bytes)\n", size);
    
    printf("  Ethernet Header:\n");
    printf("    Source MAC: ");
    print_mac(eth_header->h_source);
    printf("\n");
    printf("    Dest MAC: ");
    print_mac(eth_header->h_dest);
    printf("\n");
    printf("    Protocol: 0x%04x (RARP)\n", ntohs(eth_header->h_proto));
    
    // 打印ARP/RARP头部信息
    printf("  RARP Header:\n");
    printf("    Hardware Type: %d\n", ntohs(arp_header->ar_hrd));
    printf("    Protocol Type: 0x%04x\n", ntohs(arp_header->ar_pro));
    printf("    Hardware Length: %d\n", arp_header->ar_hln);
    printf("    Protocol Length: %d\n", arp_header->ar_pln);
    printf("    Operation: %d ", ntohs(arp_header->ar_op));
    
    switch(ntohs(arp_header->ar_op)) {
        case 3:
            printf("(RARP Request)\n");
            break;
        case 4:
            printf("(RARP Reply)\n");
            break;
        default:
            printf("(Unknown)\n");
            break;
    }
    
    if (ntohs(arp_header->ar_hrd) == 1 && ntohs(arp_header->ar_pro) == 0x0800) {
        unsigned char *arp_data = (unsigned char *)(arp_header + 1);
        
        printf("    Sender MAC: ");
        print_mac(arp_data);
        printf("\n");
        
        printf("    Sender IP: ");
        print_ip(arp_data + 6);
        printf("\n");
        
        printf("    Target MAC: ");
        print_mac(arp_data + 10);
        printf("\n");
        
        printf("    Target IP: ");
        print_ip(arp_data + 16);
        printf("\n");
    }
    
    printf("\n");
}

int main() {
    int sockfd;
    unsigned char buffer[BUFFER_SIZE];
    int packet_size;
    
    printf("Starting RARP packet consumer...\n");
    
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_RARP));
    if (sockfd < 0) {
        perror("Socket creation failed");
        printf("Note: This program requires root privileges to create raw sockets\n");
        exit(1);
    }
    
    printf("AF_PACKET socket created successfully for RARP packets\n");
    printf("Socket file descriptor: %d\n", sockfd);
    printf("Listening for RARP packets... (Press Ctrl+C to stop)\n\n");
    
    while (1) {
        packet_size = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, NULL, NULL);
        
        if (packet_size < 0) {
            perror("Packet receive failed");
            continue;
        }
        
        struct ethhdr *eth_header = (struct ethhdr *)buffer;
        if (ntohs(eth_header->h_proto) == ETH_P_RARP) {
            process_rarp_packet(buffer, packet_size);
        }
    }
    
    close(sockfd);
    return 0;
}
