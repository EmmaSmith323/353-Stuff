#include <stdio.h>
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <unistd.h>
#include "pcap.h"
#include <vector>


// The following definitions are from http://www.tcpdump.org/pcap.html 
	/* Ethernet addresses are 6 bytes */
	#define ETHER_ADDR_LEN	6
	/* ethernet headers are always exactly 14 bytes */
	#define SIZE_ETHERNET 14
	#define IPv4_ETHERTYPE 0x800
	/* Ethernet header */
	struct sniff_ethernet {
		u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
		u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
		u_short ether_type; /* IP? ARP? RARP? etc */
	};
	/* IP header */
	struct sniff_ip {
		u_char ip_vhl;		/* version << 4 | header length >> 2 */
		u_char ip_tos;		/* type of service */
		u_short ip_len;		/* total length */
		u_short ip_id;		/* identification */
		u_short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
		u_char ip_ttl;		/* time to live */
		u_char ip_p;		/* protocol */
		u_short ip_sum;		/* checksum */
		struct in_addr ip_src,ip_dst; /* source and dest address */
	};
	#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
	#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

	/* TCP header */
	typedef u_int tcp_seq;

	struct sniff_tcp {
		u_short th_sport;	/* source port */
		u_short th_dport;	/* destination port */
		tcp_seq th_seq;		/* sequence number */
		tcp_seq th_ack;		/* acknowledgement number */
		u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
		u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		u_short th_win;		/* window */
		u_short th_sum;		/* checksum */
		u_short th_urp;		/* urgent pointer */
};
	pcap_t *handle;			/* Session handle */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	const struct sniff_ethernet *ethernet;	/* The ethernet header */
	const struct sniff_ip *ipHead;	/* The IP header */
	const struct sniff_tcp *tcpHead; /* The TCP header */
	u_int           size_ipHead;
	u_int			size_tcpHead;
	char           *source, *destination;

// End of http://www.tcpdump.org/pcap.html code

//def of the struct for input information from command line
 struct Info {
   int countOfPackets;
   int countOfBytes;
   u_char *srcIP; 
   u_char *dstIP;
	Info(int p, int b, u_char *src, u_char *dst) {
		countOfPackets = p;
		countOfBytes = b;
		srcIP = src;
		dstIP = dst;
	}
};
//def of struct for analysis information from pcap
struct Packets {
   int countOfPackets;
   int countOfBytes;
   u_char *srcIP; 
   u_char *dstIP;
   Packets() {
		countOfPackets = 0;
		countOfBytes = 0;
		srcIP = 0;
		dstIP = 0;
	}
}

//init of the cmd input struct & stored info from packets
 u_char src[ETHER_ADDR_LEN];
 u_char dst[ETHER_ADDR_LEN];
 Info *info = new Info(0, 0, src, dst);

std::vector<Packets> packetInfo;
 
 
void processPacket(u_char *args,  const struct pcap_pkthdr *pkthdr, const u_char *packet);

	


int main( int argc, char *argv[] ){
	printf("Starting test \n");
	char *pcapFile = (char *)malloc(1000);
	strcpy(pcapFile, "udp-multipleIP-6.pcap");
	
	handle = pcap_open_offline(pcapFile, errbuf);

	printf("Packet Count: %d\n", info->countOfPackets);
	printf("Recieved Packet Size: %d\n", info->countOfBytes);
	pcap_loop(handle, -1, processPacket, (u_char *)&info);
	
		/* Grab a packet */
		//packet = pcap_next(handle, &header);
		/* Print its length */
		//printf("Jacked a packet with length of [%d]\n", header.len);
		/* And close the session */
		pcap_close(handle);
		return(0);
}



void processPacket(u_char *args,  const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	Info *info = (Info *)args;
	struct in_addr srcIp, dstIp;
	
	ethernet = (struct sniff_ethernet*)(packet);
	ipHead = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ipHead = IP_HL(ipHead)*4;
	if (size_ipHead < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ipHead);
		return;
	}
	srcIp = ipHead->ip_src;
	dstIp = ipHead->ip_dst;
	
	
	info->countOfPackets = info->countOfPackets + 1;
	printf("Packet Count: %d\n", info->countOfPackets);
	info->countOfBytes = info->countOfBytes + pkthdr->len;
	printf("Recieved Packet Size: %d\n", pkthdr->len);
	printf("Total Byte Count: %d\n", info->countOfBytes);
	printf("Source IP: %s\n", inet_ntoa(srcIp));
	printf("Destination IP: %s\n", inet_ntoa(dstIp));
	printf("\n");
	
		
	
	
	
	
	
	
	
	
	
		
	};
	
	