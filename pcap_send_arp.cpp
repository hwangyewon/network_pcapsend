#include <stdlib.h>
#include <stdio.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <string>
#include <cstring>
#define PCAP_OPENFLAG_PROMISCUOUS   1

using namespace std;


int main(int argc, char **argv)
{
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_char packet[100];
    int i;

    ether_arp ether;
    ether_arp* ether_ptr=&ether;




    /* Check the validity of the command line */
    if (argc != 3) //
    {
        printf("usage: %s %s ip address (e.g. 'pcap_send_arp eth0 192.0.0.0", argv[0], argv[1]);
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

    //source hardware address
    // for(int i=0; i<6;i++){
    //     ether.arp_sha[i]=0xff;
    // }

    // ether.arp_spa=0xc0a8000f;


    /* Supposing to be on ethernet, set mac destination to FF:FF:FF:FF:FF:FF */
    packet[0]=0xff;
    packet[1]=0xff;
    packet[2]=0xff;
    packet[3]=0xff;
    packet[4]=0xff;
    packet[5]=0xff;
    
    /* set mac source to 2:2:2:2:2:2 */
    packet[6]=2;
    packet[7]=2;
    packet[8]=2;
    packet[9]=2;
    packet[10]=2;
    packet[11]=2;

    packet[12]=0x08;
    packet[13]=0x06;

    packet[14]=0x00;
    packet[15]=0x01;

    packet[16]=0x08;
    packet[17]=0x00;

    packet[18]=0x06;

    packet[19]=0x04;

    packet[20]=0x00;
    packet[21]=0x01;

    //sender MAC address
    packet[22]=2;
    packet[23]=2;
    packet[24]=2;
    packet[25]=2;
    packet[26]=2;
    packet[27]=2;

    //sender IP address
    packet[28]=0xc0;
    packet[29]=0xa8;
    packet[30]=0x00;
    packet[31]=0x10;

    //Target MAC address
    packet[32]=0x00;
    packet[33]=0x00;
    packet[34]=0x00;
    packet[35]=0x00;
    packet[36]=0x00;
    packet[37]=0x00;

    //Target IP address
    struct sockaddr_in target_ip;

    if(!inet_aton(argv[2], &target_ip.sin_addr))
    {
        printf("Conversion Error \n");
        return -1;
    }else
    {
        char s1[10];
        char s2[5];
        u_int num2[4];
        u_int num1=target_ip.sin_addr.s_addr;
        
        sprintf(s1,"%x", num1);

        string str1=" ";
        str1=s1;
        string str2;
        string str3="0x";

        for(int i=0;i<7;i+=2)
        {
            str2.clear();
            str3.clear();
            str3 = "0x";
            str2 = str1.substr(i, 2);
            str3 = str3 + str2;
            strcpy(s2, str3.c_str());
            num2[i/2] = strtol(s2, NULL, 16);
        }

        int i=0;
        for(int j=41;j>37;j--)
        {
            packet[j]=num2[i];
            i++;
        }
        

    }
        




    
    
    /* Fill the rest of the packet */
    for(i=42;i<100;i++)
    {
        packet[i]=0;
    }

    /* Send down the packet */
    if (pcap_sendpacket(fp, packet, 100 /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
        return -1;
    }

    return 0;
}