#include <stdio.h>
#include <iostream>
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <netdb.h>
#include <unistd.h>
#include "pcap.h"
#include <vector>
#include "signal.h"
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <cstdlib>
#include <ctime>
#include <stdlib.h>
#include <time.h>



// The following definitions are from http://www.tcpdump.org/pcap.html
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

struct udphdr {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	short	uh_ulen;		/* udp length */
	u_short	uh_sum;			/* udp checksum */
};

	pcap_t *handle;			/* Session handle */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	const struct sniff_ethernet *ethernet;	/* The ethernet header */
	const struct sniff_ip *ipHead;	/* The IP header */
	const struct sniff_tcp *tcpHead; /* The TCP header */
	const struct udphdr *udpHead;
	u_int           size_ipHead;
	u_int			size_tcpHead;
	char           *source, *destination;

// End of http://www.tcpdump.org/pcap.html code



};


//declaration of needed vars
	char *logFilename;
  bool numWatchdogs
	FILE *logfile;

int main(int argc, char *argv[]) {

/*
desman [ -w filename ] [-n number]
where
-w, --write Write the output in the specified log file
-n, --number The number of watchdogs in the NIDS

*/

	//Loop through command line words
	char error[10000] = "desman [ -w filename ] [-n number] \n   where \n   -w, --write Write the output in the specified log file \n  -n, --number The number of watchdogs in the NIDS \n";
  if(argc < 2) {
		printf("%s", error);
		return -1;
	}

	for(int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-w") == 0 || strcmp(argv[i], "--write") == 0 ) {
			logFilename = argv[i+1];
			i++;
		}
		else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--number") == 0 ) {
			numWatchdogs = argv[i+1];
			i++;
		}

	}//end of for that loops through cmd line args






	//Print out stuff here!
	//open logfile
	logfile= fopen(logFilename, "w+");
	char log[1000];
	char numChar[100];





	fclose(logfile);
	return(0);

}



void processPacket(u_char *args,  const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	packetIndex++;
	std::vector<Packets*>* packetInfo = (std::vector<Packets*>*) args;
	struct in_addr srcIp;
	struct in_addr dstIp;
	u_short srcPort;
	u_short dstPort;
	u_char protocol;
	int length;

	ethernet = (struct sniff_ethernet*)(packet);
	ipHead = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ipHead = IP_HL(ipHead)*4;
	srcIp = ipHead->ip_src;
	dstIp = ipHead->ip_dst;
	length = ntohs(ipHead->ip_len);
	protocol = ipHead->ip_p;

	if (protocol == IPPROTO_UDP) {//UDP
		udpHead = (const struct udphdr*)(packet+SIZE_ETHERNET+size_ipHead);
		srcPort = udpHead->uh_sport;
		dstPort = udpHead->uh_dport;
	} else { //TCP
		tcpHead = (const struct sniff_tcp*)(packet+SIZE_ETHERNET+size_ipHead);
		srcPort = tcpHead->th_sport;
		dstPort = tcpHead->th_dport;
	}

	printf("Recieved Packet Size: %d\n", length);
	printf("Source IP: %s\n", inet_ntoa(srcIp));
	printf("Destination IP: %s\n", inet_ntoa(dstIp));
	printf("\n");











}//end of part 2 stuff



	};
