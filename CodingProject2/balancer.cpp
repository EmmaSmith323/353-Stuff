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


//Test cmd lines
//   ./balancer -r udp-multipleIP-6.pcap -l logfile.txt -s -d -p -b
//   ./balancer -r tcp-multipleIP-97.pcap -l logfile.txt -s -d -p -b
//   ./balancer -i eth1 -l logfile.txt -s -d -p -b
//   ./balancer -r udp-multipleIP-6.pcap -l logfile.txt -w 3 -c 33:33:34
//   ./balancer -r tcp-multipleIP-97.pcap -l logfile.txt -w 3 -c 33:33:34



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


//def of struct for analysis information from pcap
struct Packets {
   int countOfPackets;
   int countOfBytes;
   struct in_addr srcIP; 
   struct in_addr dstIP;
    Packets(int cPackets, int cBytes, struct in_addr src, struct in_addr dst) {
		countOfPackets = cPackets;
		countOfBytes = cBytes;
		srcIP = src;
		dstIP = dst;
	}
};
//def of struct for holding webserver information
struct Webserver {
	char *wsFilename;
	int percentage;
	FILE *wbFile;
	Webserver(char *name, int perc) {
		wsFilename = name;
		percentage = perc;
	}
};
//def of struct for flows
struct Flow {
	struct in_addr srcIP;
	struct in_addr dstIP;
	u_short srcPort;
	u_short dstPort;
	u_char protocol;
	int webserver;
	int flowIndex;
	Flow(struct in_addr sIP, struct in_addr dIP, u_short sPort, u_short dPort, u_char prot, int server, int flow) {
		srcIP = sIP;
		dstIP = dIP;
		srcPort = sPort;
		dstPort = dPort;
		protocol = prot;
		webserver = server;
		flowIndex = flow;
	}
	//equals operator for ease of use later
	bool operator==(const Flow& other) const {
		char addr1[100];
		char addr2[100];
		char addr3[100];
		char addr4[100];
		strcpy(addr1, inet_ntoa(srcIP));
		strcpy(addr2, inet_ntoa(other.srcIP));
		strcpy(addr3, inet_ntoa(dstIP));
		strcpy(addr4, inet_ntoa(other.dstIP));
		if(strcmp(addr1, addr2)==0 && strcmp(addr3, addr4)==0) { //IPs are same
			if(srcPort==other.srcPort && dstPort==other.srcPort) { //Ports are same
				if(protocol == other.protocol) { //protocol same
					return true;
				}
			}
		}
		return false;
	}
};
	
//declaration of the callback function in the pcap loop
	void processPacket(u_char *args,  const struct pcap_pkthdr *pkthdr, const u_char *packet);
//declaration of handle func for ctrl c
	void handleCtrlC(int signal);
	
//declaration of needed vars
	char *devInterface;
	char *pcapFilename;
	char *logFilename; 
	int numWebserver;
	char config[1000];
	bool packetCounts = false;
	bool byteCounts = false;
	bool srcAnalysis = false;
	bool dstAnalysis = false;
	bool reading = false;
	bool interface = false;
	bool balancingMode = false;
	int packetIndex;
//init of the storing of packet info
	std::vector<Packets*>* packetInfo;
//init of the storing of webservers
	std::vector<Webserver*>* webserverInfo;
//init of the storing of Flows 
	std::vector<Flow*>* flowInfo;

	FILE *logfile;
	
int main(int argc, char *argv[]) {

/*
USAGE
Command Line Options Analysis Mode:
> balancer [-r filename] [-i interface] [ -l filename ] [-p] [-b] [-s] [-d]
where
-r, --read Read the specified pcap file
-i, --interface Listen on the specified interface
-l, --logfile Logfile with the summary report
-p, --packet Output packet counts
-b, --byte Output byte counts
-s, --src Analyze based on source IP
-d, --dst Analyze based on destination IP

Command Line Options Balancing Mode:
> balancer [-r filename] [-i interface] [-w num] [ -l filename ] [-c configpercent]
where
-r, --read Read the specified pcap file
-i, --interface Listen on the specified interface
-l, --logfile Logfile with the summary report
-c, --config Percentage of flows to balance across each server
-w, --webserver The number of webservers to balance across
*/

	//instantiations of vecots
	packetInfo = new std::vector<Packets*>();
	webserverInfo = new std::vector<Webserver*>();
	flowInfo = new std::vector<Flow*>();
	//Loop through command line words
	char error[10000] = "USAGE \n Command Line Options Analysis Mode: \n > balancer [-r filename] [-i interface] [ -l filename ] [-p] [-b] [-s] [-d] \n where \n -r, --read Read the specified pcap file \n -i, --interface Listen on the specified interface \n -l, --logfile Logfile with the summary report \n -p, --packet Output packet counts \n -b, --byte Output byte counts \n -s, --src Analyze based on source IP \n -d, --dst Analyze based on destination IP \n \n Command Line Options Balancing Mode: \n > balancer [-r filename] [-i interface] [-w num] [ -l filename ] [-c configpercent] \n where \n -r, --read Read the specified pcap file \n -i, --interface Listen on the specified interface \n -l, --logfile Logfile with the summary report \n -c, --config Percentage of flows to balance across each server \n -w, --webserver The number of webservers to balance across";	
	if(argc < 2) {
		printf("%s", error);
		return -1;
	}
	
	
	for(int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--read") == 0 ) { 
			pcapFilename = argv[i+1];
			reading = true;
			i++;
		}
		else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interface") == 0 ) { 
			devInterface = argv[i+1];
			interface = true;
			i++;
		}
		else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--logfile") == 0 ) { 
			logFilename = argv[i+1];
			i++;
		}
		else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--packet") == 0 ) { 
			packetCounts = true;
		}
		else if (strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--byte") == 0 ) { 
			byteCounts = true;
		}
		else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--src") == 0 ) { 
			srcAnalysis = true;
		}
		else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--dst") == 0 ) {   
			dstAnalysis = true;
		}	
		else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) {
			strcpy(config, argv[i+1]);
			i++;
		}
		else if (strcmp(argv[i], "-w") == 0 || strcmp(argv[i], "--webserver") == 0) {
			balancingMode = true;
			numWebserver = atoi(argv[i+1]);
			i++;
		}
	
	}//end of while that loops through cmd line args
 
	//deals with the input and creates webservers adding them to vector
	char * split;
	char name[1000];
	char iChar[100];
	int pct;
	split = strtok (config,":");
	//Create webserver files
	for(int i = 1; i <= numWebserver; i++) {
			sprintf(iChar, "%d", i);
			strcpy(name, "webserver.");
			strcat(name, iChar);
			pct = atoi(split);
			struct Webserver *newWS = new Webserver(name, pct);
			webserverInfo->push_back(newWS);			
			split = strtok (NULL, ":");
	}

	//setup singal to handle ctrl c.
	//The SIGINT (“program interrupt”) signal is sent when the user types the INTR character (normally C-c). 
	signal(SIGINT, handleCtrlC);
	if(reading == true) {
		//open offline - only do for read
		handle = pcap_open_offline(pcapFilename, errbuf);
	} else if(interface == true){
		printf("Interface  %s \n", devInterface);
		//open live - from interface
		handle = pcap_open_live(devInterface, BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) {
		 fprintf(stderr, "Couldn't open device %s: %s\n", devInterface, errbuf);
		
	 }
	}

	packetIndex = 0;
	
	// loop through all packets and use callback function
	pcap_loop(handle, -1, processPacket, (u_char *)packetInfo);	

	
	// close when done
	pcap_close(handle);
	

	
	//Print out stuff here!
	//open logfile
	logfile= fopen(logFilename, "w+");
	char log[1000];	
	char numChar[100]; 
	

	//PART 1 CODE
	//depending on what flags were given on cmd line changes outputs.
	if(srcAnalysis & !dstAnalysis) {
	
		for (unsigned int i = 0; i < packetInfo->size(); i++){
			strcpy(log, inet_ntoa((packetInfo->at(i))->srcIP));
			strcat(log, "\t");
			if(packetCounts){
				sprintf(numChar, "%d", (packetInfo->at(i))->countOfPackets);
				strcat(log, numChar);
				strcat(log, "\t");
			}
			if(byteCounts){
				sprintf(numChar, "%d", (packetInfo->at(i))->countOfBytes);
				strcat(log, numChar);
				strcat(log, "\t");
			}
			strcat(log, "\n");
			fprintf(logfile, "%s", log);
			printf("%s", log);
			fflush(logfile);
		}
		
	} else if(!srcAnalysis & dstAnalysis) {

		for (unsigned int i = 0; i < packetInfo->size(); i++){
			strcpy(log, inet_ntoa((packetInfo->at(i))->dstIP));
			strcat(log, "\t");
			if(packetCounts){
				sprintf(numChar, "%d", (packetInfo->at(i))->countOfPackets);
				strcat(log, numChar);
				strcat(log, "\t");
			}
			if(byteCounts){
				sprintf(numChar, "%d", (packetInfo->at(i))->countOfBytes);
				strcat(log, numChar);
				strcat(log, "\t");
			}
			strcat(log, "\n");
			fprintf(logfile, "%s", log);
			printf("%s", log);
			fflush(logfile);
		}
	} else if(srcAnalysis & dstAnalysis) {

		for (unsigned int i = 0; i < packetInfo->size(); i++){
			strcpy(log, inet_ntoa((packetInfo->at(i))->srcIP));
			strcat(log, "\t");
			strcat(log, inet_ntoa((packetInfo->at(i))->dstIP));
			strcat(log, "\t");
			if(packetCounts){
				sprintf(numChar, "%d", (packetInfo->at(i))->countOfPackets);
				strcat(log, numChar);
				strcat(log, "\t");
			}
			if(byteCounts){
				sprintf(numChar, "%d", (packetInfo->at(i))->countOfBytes);
				strcat(log, numChar);
				strcat(log, "\t");
			}
			strcat(log, "\n");
			fprintf(logfile, "%s", log);
			printf("%s", log);
			fflush(logfile);
		}
	}
	
	

	
	
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
	
	bool found = false;
	char addr1[100];
	char addr2[100];
	char addr3[100];
	char addr4[100];
	if(srcAnalysis & !dstAnalysis) {
			found = false;	
		for (unsigned int i = 0; i < packetInfo->size(); i++){
				strcpy(addr1, inet_ntoa((packetInfo->at(i))->srcIP));
				strcpy(addr2, inet_ntoa(srcIp));
				printf("%s \n %s \n ", inet_ntoa((packetInfo->at(i))->srcIP), inet_ntoa(srcIp));
				printf("%s \n %s \n ", addr1, addr2);
				printf("%d \n", strcmp(addr1, addr2));
			if( strcmp(addr1, addr2) == 0 ){
				found = true;
				(packetInfo->at(i))->countOfBytes += length;
				(packetInfo->at(i))->countOfPackets += 1;
				break;
			}
		}
		if(found == false) {
			struct Packets *newPack = new Packets(1, length, srcIp, dstIp);
			packetInfo->push_back(newPack);
		}
		
	} else if(dstAnalysis & !srcAnalysis){
		found = false;
		for (unsigned int i = 0; i < packetInfo->size(); i++) {
			strcpy(addr1, inet_ntoa((packetInfo->at(i))->dstIP));
			strcpy(addr2, inet_ntoa(dstIp));
			printf("%s \n %s \n ", inet_ntoa((packetInfo->at(i))->dstIP), inet_ntoa(dstIp));
			printf("%s \n %s \n ", addr1, addr2);
			printf("%d \n", strcmp(addr1, addr2));
			
			if( strcmp(addr1, addr2) == 0 ) {
				found = true;
				(packetInfo->at(i))->countOfBytes += length;
				(packetInfo->at(i))->countOfPackets += 1;
				break;
			}
		}
		
		if(found == false) {
			struct Packets *newPack = new Packets(1, length, srcIp, dstIp);
			packetInfo->push_back(newPack);
		}
	} else if(dstAnalysis & srcAnalysis) {
		found = false;
		for (unsigned int i = 0; i < packetInfo->size(); i++) {
			strcpy(addr1, inet_ntoa((packetInfo->at(i))->srcIP));
			strcpy(addr2, inet_ntoa(srcIp));
			strcpy(addr3, inet_ntoa((packetInfo->at(i))->dstIP));
			strcpy(addr4, inet_ntoa(dstIp));
			if( ( strcmp(addr1, addr2) == 0 ) && ( strcmp(addr3, addr4) == 0 ) ) {
				found = true;
				(packetInfo->at(i))->countOfBytes += length;
				(packetInfo->at(i))->countOfPackets += 1;
				break;
			}
		}
		if(found == false) {
			struct Packets *newPack = new Packets(1, length, srcIp, dstIp);
			packetInfo->push_back(newPack);
		}
		
	} 
	
	//Part 2 stuff
if(balancingMode) {	
	struct Flow *newFlow = new Flow(srcIp, dstIp, srcPort, dstPort, protocol, -1, -1); 
	//Check for same flow 
	//- if already exists, send to same server  
	//- if not, add to flowInfo and rand choose server to send
	bool server = false;
	for(unsigned int i = 0; i < flowInfo->size(); i++) {
		if(&flowInfo->at(i) == &newFlow) {
			newFlow->webserver = flowInfo->at(i)->webserver;
			newFlow->flowIndex = i+1;
			server = true;
			printf("updated packet in vect \n \n");
			break;
		}
	}
	if(server == false) {
		//TODO:CHOOSE FLOWS BASED ON PROBABILITY???
		int val = rand()%(webserverInfo->size()-1 + 1);
		newFlow->webserver = val;
		newFlow->flowIndex = flowInfo->size() + 1;
		flowInfo->push_back(newFlow);
		
	}
	
	
	//Main logfile
	logfile = fopen(logFilename, "w+");
	if(logfile == NULL) {
		printf("err");
	}
	printf("%s \n", logFilename);
	char log[10000];	
	fflush(logfile);
	sprintf(log, "%d\t%d\t%d\n", packetIndex, newFlow->flowIndex, newFlow->webserver);
	fprintf(logfile, "%s", log);
	printf("%s", log);
	fflush(logfile);

	fclose(logfile);
	
	
	//Webserver file
	Webserver* ws = webserverInfo->at(newFlow->webserver);
	ws->wbFile = fopen(ws->wsFilename, "w+");
	if(ws->wbFile == NULL) {
		printf("err");
	}
	printf("%s \n", ws->wsFilename);

	fflush(ws->wbFile);
	 strcpy(addr1, inet_ntoa(srcIp));
	 strcpy(addr2, inet_ntoa(dstIp));
	sprintf(log, "%d\t%ld.%ld\t%s\t%s\t%d\t%d\t%d\t%d\n", packetIndex, pkthdr->ts.tv_sec, pkthdr->ts.tv_usec, addr1, addr2, srcPort, dstPort, protocol, length);
	
	fprintf(ws->wbFile, "%s", log);
	printf("%s", log);
	fflush(ws->wbFile);

	fclose(ws->wbFile);
	
	
	
	
	

}//end of part 2 stuff	


	
	};
	
	void handleCtrlC(int signal) {
		printf("User pressed crtl c, quit loop");
		pcap_breakloop (handle);  
	}
	
	