#include <stdlib.h>
#include <stdio.h>
#include <net/if_arp.h>
#include <pcap.h>
#include <string.h>

struct arp{
    unsigned char hdr[2];      // hardware type
    unsigned char p[2];        // protocol  
    unsigned char hl;          // hardware length
    unsigned char pl;          // protocol length 
    unsigned char op[2];       // opcode
    unsigned char sha[6];       // sender mac
    unsigned char spa[4];      // sender ip  
    unsigned char tha[6];      // target mac 
    unsigned char tpa[4];      // target ip  
};

int main(int argc, char **argv)
{
pcap_t *fp;
char errbuf[PCAP_ERRBUF_SIZE];
u_char packet[100];
int i;

    /* Check the validity of the command line */
    if (argc != 2)
    {
        printf("usage: %s interface (e.g. 'rpcap://eth0')", argv[0]);
        return -1;
    }
    
    /* Open the output device */
    if ( (fp= pcap_open_live(argv[1],            // name of the device
                        100,                // portion of the packet to capture (only the first 100 bytes)
                        PCAP_OPENFLAG_PROMISCUOUS,  // promiscuous mode
                        1000,               // read timeout
                        errbuf              // error buffer
                        ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", argv[1]);
        return -1;
    }

    /* Supposing to be on ethernet, set mac destination to 1:1:1:1:1:1 */
    packet[0]=1;
    packet[1]=1;
    packet[2]=1;
    packet[3]=1;
    packet[4]=1;
    packet[5]=1;
    
    /* set mac source to 2:2:2:2:2:2 */
    packet[6]=2;
    packet[7]=2;
    packet[8]=2;
    packet[9]=2;
    packet[10]=2;
    packet[11]=2;

    // type = arp
    packet[12] = 0x08;
    packet[13] = 0x06;
    
    struct arp arp;

    //protocol, op ..

    //ethernet
    arp.hdr[0] = 0x00;
    arp.hdr[1]=0x01;

    arp.p[0]= 0x08;
    arp.p[1]= 0x00;

    arp.hl = 0x06;
    arp.pl = 0x04;

    //arp operation
    arp.op[0]  =0x00;
    arp.op[1]  =0x01;

    //ethernet/IP arp message
    
    //SENDER MAC - 1:1:1:1:1
    arp.sha[0] = 0x01;
    arp.sha[1] = 0x01;
    arp.sha[2] = 0x01;
    arp.sha[3] = 0x01;
    arp.sha[4] = 0x01;
    arp.sha[5] = 0x01;

    //SENDER ip - 1:1:1:1
    arp.spa[0] = 0x01;
    arp.spa[1] = 0x01;
    arp.spa[2] = 0x01;
    arp.spa[3] = 0x01;

    //TARGET MAC : 00:00:00:00:00
    arp.tha[0] = 0x00;
    arp.tha[1] = 0x00;
    arp.tha[2] = 0x00;
    arp.tha[3] = 0x00;
    arp.tha[4] = 0x00;
    arp.tha[5] = 0x00;

    //TARGET ip : 17:17:17:17
    arp.tpa[0] = 0x11;
    arp.tpa[1] = 0x11;
    arp.tpa[2] = 0x11;
    arp.tpa[3] = 0x11;

    memcpy(packet+14, &arp, sizeof(struct arp));

    /* Send down the packet */
    if (pcap_sendpacket(fp, packet, 100 /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
        return -1;
    }

    return 0;
}