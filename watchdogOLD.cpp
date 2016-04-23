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
#include <mutex>
#include <pthread.h>


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



//def of struct for flows
struct Flow {
	struct in_addr srcIP;
	struct in_addr dstIP;
	u_short srcPort;
	u_short dstPort;
	u_char protocol;
	int flowIndex;
	Flow(struct in_addr sIP, struct in_addr dIP, u_short sPort, u_short dPort, u_char prot, int flow) {
		srcIP = sIP;
		dstIP = dIP;
		srcPort = sPort;
		dstPort = dPort;
		protocol = prot;
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
	#define PORT 11353

	char *devInterface;
	char *pcapFilename;
	char *logFilename;
	char *desmanIP;
	int myUID = -1;
	int currReport = 1;
	std::vector<Flow*>* flowInfo;
	int numBytes;
	int numPackets;
	timeval timePeriod;
	time_t timeDelta;
	time_t timeNow;
	bool first = true;

	bool reading = false;
	bool interface = false;

	FILE *logfile;
		
	int clientSocket;
	
	std::mutex logfileMutex;
	
	

int main(int argc, char *argv[]) {

/*
USAGE
watchdog [-r filename] [-i interface] [ -w filename ] [-c desmanIP]
where
-r, --read Read the specified file
-i, --interface Listen on the specified interface
-w, --write Write the output in the specified log file
-c, --connect Connect to the specified IP address for the desman
 
./watchdog -r tcp-twoIP-200.pcap -w wd1.txt -c 10.1.1.2
./watchdog -i eth2 -w wd1.txt -c 10.1.1.3 & ping 10.1.1.3


*/

	//Loop through command line words
	char error[10000] = "USAGE /n	watchdog [-r filename] [-i interface] [ -w filename ] [-c desmanIP] /n 	where/n 	-r, --read Read the specified file /n	-i, --interface Listen on the specified interface /n 	-w, --write Write the output in the specified log file /n 	-c, --connect Connect to the specified IP address for the desman \n";
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
		else if (strcmp(argv[i], "-w") == 0 || strcmp(argv[i], "--write") == 0 ) {
			logFilename = argv[i+1];
			i++;
		}
		else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--connect") == 0 ) {
			desmanIP = argv[i+1];
			i++;
		}

	}//end of for that loops through cmd line args
	
	flowInfo = new std::vector<Flow*>();
	numBytes = 0;
	numPackets = 0;
	
	//open logfile
	logfile= fopen(logFilename, "w+");
	char log[1000];
	char buffer[1000];
	
	struct sockaddr_in serverAddr;
	socklen_t addr_size;
	addr_size = sizeof serverAddr;
	
	//configure settings
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(PORT);
	serverAddr.sin_addr.s_addr = inet_addr(desmanIP);
	memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);
	

	clientSocket = socket(AF_INET, SOCK_STREAM, 0);
	
		printf("about to connect \n");
		fflush(stdout);
	
	//make connection
	connect(clientSocket,(struct sockaddr *) &serverAddr, addr_size);	
	char host[1000];
	getnameinfo((struct sockaddr *)&serverAddr, addr_size, host, sizeof(host), NULL, 0, 0);	
	
	//Connect to desman and get UID
	logfileMutex.lock();
	strcpy(log, "Connecting to desman at ");
	strcat(log, host);
	strcat(log, "\n");
	fprintf(logfile, "%s", log);
	printf("%s", log);
	fflush(logfile);
	fflush(stdout);
	logfileMutex.unlock();
	
	
	while(1) {
		memset(buffer,'\0', sizeof buffer);
		recv(clientSocket, buffer, 1000, 0);
		if(buffer[0] != 0) {
			break;
		}
	}
	// get UID
	
	//TODO FIX THIS   myUID = atoi(buffer[4]);
	logfileMutex.lock();
	strcpy(log, "Received ");
	strcat(log, buffer);
	strcat(log, "\n");
	fprintf(logfile, "%s", log);
	printf("%s", log);
	fflush(logfile);
	logfileMutex.unlock();

	
	while(1) {
		memset(buffer,'\0', sizeof buffer);
		recv(clientSocket, buffer, 1000, 0);
		if(strcmp(buffer, "start") == 0) {
			break;
		}
	}
	
	//wait for start command
	logfileMutex.lock();
	strcpy(log, "Received start… \n");
	fprintf(logfile, "%s", log);
	printf("%s", log);
	fflush(logfile);
	logfileMutex.unlock();
	
	if(reading == true) { //from pcap file, so base reports on timestamp
		timePeriod.tv_sec = 0;
		
		
	} else if (interface == true) { // from interface so base reports on timer
		time(&timeDelta);
		
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
	u_char* info = new u_char[1024]();

	//loop through all packets and use callback function
	pcap_loop(handle, -1, processPacket, info);


	
	
	
	// close when done
	pcap_close(handle);

	fclose(logfile);
	return(0);


};





void processPacket(u_char *args,  const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	
	printf("processing packet  \n");
	fflush(stdout);
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
	} else if(protocol == IPPROTO_TCP) { //TCP
		tcpHead = (const struct sniff_tcp*)(packet+SIZE_ETHERNET+size_ipHead);
		srcPort = tcpHead->th_sport;
		dstPort = tcpHead->th_dport;
	}
	
	if(reading == true) { //based of of timestamps!!!
		if(pkthdr->ts.tv_sec > timePeriod.tv_sec) { //next time period
			logfileMutex.lock();
			char numChar [100]; 
			char rLog [10000];
			
			strcpy(rLog, "report "); //report
			sprintf(numChar, "%d", currReport);
			strcat(rLog, numChar); //reportnumber
			strcat(rLog, " ");
			sprintf(numChar, "%d", numPackets);
			strcat(rLog, numChar); // packets
			strcat(rLog, " ");
			sprintf(numChar, "%d", numBytes);
			strcat(rLog, numChar); //bytes
			strcat(rLog, " ");
			sprintf(numChar, "%d", flowInfo->size());
			strcat(rLog, numChar); //flows	
			strcat(rLog, "\n \0");
			//Send to desman
			sleep(1);
			send(clientSocket, rLog, strlen( rLog), 0);
			//std::cin.get();
			//Log to file
			fprintf(logfile, "%s", rLog);
			printf("%s", rLog);
			fflush(logfile);
			fflush(stdout);
			logfileMutex.unlock();

			//reset values
			numBytes = 0;
			numPackets = 0;
			flowInfo->clear();
			currReport++;
	
			timePeriod.tv_sec++;
		}
	} else { // based on timer, do nothing?!?!?!
	printf("inter check time  \n");
	
	time(&timeNow);
	struct tm * timeinfo;
	
	timeinfo = localtime ( &timeDelta );
	printf ( "timedelta : %s", asctime (timeinfo) );
    timeinfo = localtime ( &timeNow );
	printf ( "timenow : %s", asctime (timeinfo) );
	printf("%f  \n",  difftime(timeNow,timeDelta));
	fflush(stdout);
		if(  difftime(timeNow,timeDelta) >= 60) {
			logfileMutex.lock();
			char numChar [100]; 
			char rLog [10000];
			
			strcpy(rLog, "report "); //report
			sprintf(numChar, "%d", currReport);
			strcat(rLog, numChar); //reportnumber
			strcat(rLog, " ");
			sprintf(numChar, "%d", numPackets);
			strcat(rLog, numChar); // packets
			strcat(rLog, " ");
			sprintf(numChar, "%d", numBytes);
			strcat(rLog, numChar); //bytes
			strcat(rLog, " ");
			sprintf(numChar, "%d", flowInfo->size());
			strcat(rLog, numChar); //flows	
			strcat(rLog, "\n \0");
			//Send to desman
			send(clientSocket, rLog, strlen( rLog), 0);
			//std::cin.get();
			//Log to file
			fprintf(logfile, "%s", rLog);
			printf("%s", rLog);
			fflush(logfile);
			fflush(stdout);
			logfileMutex.unlock();

			//reset values
			numBytes = 0;
			numPackets = 0;
			flowInfo->clear();
			currReport++;
	
			timeDelta = timeNow;
		}
	}

	//add to the numPackets and numBytes
	numPackets++;
	numBytes += length;
	//check flow, and add if needed
	bool duplicate = false;
	struct Flow *newFlow = new Flow(srcIp, dstIp, srcPort, dstPort, protocol, -1); 
	for(unsigned int i = 0; i < flowInfo->size(); i++) {
		if(&flowInfo->at(i) == &newFlow) {
			duplicate = true;
			break;
		}
	}
	if(duplicate == false) {
		newFlow->flowIndex = flowInfo->size() + 1;
		flowInfo->push_back(newFlow);		
	}

	
};

void handleCtrlC(int signal) {
	printf("User pressed crtl c, quit loop");
	pcap_breakloop (handle);  
}
	
	
