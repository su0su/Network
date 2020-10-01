#include<arpa/inet.h>
#include<net/ethernet.h>
#include<netinet/ip.h>
#include<cstdio>
#include<iostream>
#include<cstring>
#include<pcap.h>
#include<stdio.h>
#include<net/if_arp.h>
#include<netinet/if_ether.h>

using namespace std;

void dump_pkt(const u_char *pkt_data, struct pcap_pkthdr* header);

void usage()
{
    printf("syntax : pcap-test <interface>\n");
    printf("sample : pcap-test wlan0\n");
}

int main(int argc,char * argv[]){
    if(argc!=2){
        usage();
        return -1;
    }

    char * dev= argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * handle =pcap_open_live(dev, BUFSIZ, 1,1000,errbuf);
    
    if(handle==nullptr){
        fprintf(stderr, "pcap_open_live(%s) return nullptr - $s\n",dev,errbuf);
    }
    
    while(true){
        struct pcap_pkthdr* header;
        const u_char * packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res ==0) continue;
        if (res==-1 | res ==-2){
            printf("pcap_next_ex return %d(%s)\n",res, pcap_geterr(handle));
            break;
        }
        dump_pkt(packet,header);
    }
    pcap_close(handle);
}

void dump_pkt(const u_char *pkt_data, struct pcap_pkthdr* header){
    struct ether_header * eth_hdr=(struct ether_header *)pkt_data;

    u_int16_t eth_type=ntohs(eth_hdr->ether_type);   //

    //if type is not IP, return function
    if(eth_type!=ETHERTYPE_ARP) return;

    struct arphdr *arp_hdr = (struct arphdr *)(pkt_data+sizeof(ether_header));
    struct ether_arp* arphdr=(struct ether_arp*)(pkt_data + sizeof(ether_header));


    u_int8_t *dst_mac=eth_hdr ->ether_dhost;
    u_int8_t *src_mac=eth_hdr->ether_shost;

    printf("\n\nPacket Info=======================\n"); 
    printf("%u bytes captured\n", header->caplen);

    printf("Dst MAC : %0x:%0x:%0x:%0x:%0x:%0x\n",
        dst_mac[0], dst_mac[1],dst_mac[2],dst_mac[3],dst_mac[4],dst_mac[5]);
    printf("Src MAC : %0x:%0x:%0x:%0x:%0x:%0x\n",
        src_mac[0], dst_mac[1],dst_mac[2],dst_mac[3],dst_mac[4],dst_mac[5]); 

    if (ntohs(arp_hdr->ar_op) == ARPOP_REQUEST){ 
        printf("\n********REQUEST********\n");        
    } else if (ntohs(arp_hdr->ar_op)==ARPOP_REPLY){
        printf("********REPLY********\n");
    }
    
    printf("Sender IP  : %s\n ", inet_ntoa(*(struct in_addr*)&arphdr->arp_spa));
    printf("Target IP  : %s\n ", inet_ntoa(*(struct in_addr*)&arphdr->arp_tpa));
}
