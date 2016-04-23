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
#include <pthread.h>
#include <mutex>


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


void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

struct fdInfo {
	int session_fd;
	int UID;
	pthread_t thread;
	char* host;
	
	fdInfo(int sFD, int uid, char* hst) {
		session_fd = sFD;
		UID = uid;
		host = hst;
	}
	
};

//declaration of needed vars
	#define PORT 11353 
	char *logFilename;
	int numWatchdogs;
	int currUID;
	FILE *logfile;
	char log[1000];
	
	std::vector<fdInfo*>* fdInfos;
	
	void* handle_watchdog(void* args);
	
	std::mutex logfileMutex;
	std::mutex totalTrafficMutex;
	
	int totalPackets = 0;
	int totalBytes = 0;
	int totalFlows = 0;
	int numReports = 0;
	
	
int main(int argc, char *argv[]) {

/*
desman [ -w filename ] [-n number]
where
-w, --write Write the output in the specified log file
-n, --number The number of watchdogs in the NIDS


./desman -w desman.txt -n 2



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
			numWatchdogs = atoi(argv[i+1]);
			i++;
		}

	}//end of for that loops through cmd line args



	//Print out stuff here!
	//open logfile
	logfile= fopen(logFilename, "w+");


	/////////////////////////////////////////////////////////////
	// Some of this code is taken and modified from http://www.microhowto.info/howto/listen_for_and_accept_tcp_connections_in_c.html and my first assignment
	const char* hostname = 0; 
	struct addrinfo hints;
	memset(&hints,0,sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE|AI_ADDRCONFIG;
	struct addrinfo* res = 0;	
	char portname[1000];
	sprintf(portname, "%d", PORT);

	
	getaddrinfo(hostname, portname, &hints, &res);
	int server_fd = socket(res->ai_family,res->ai_socktype,res->ai_protocol);
	if (server_fd == -1) {	printf("bad server_fd \n"); return -1;	}
	int reuseaddr=1;
	setsockopt(server_fd,SOL_SOCKET,SO_REUSEADDR,&reuseaddr,sizeof(reuseaddr));
	bind(server_fd,res->ai_addr,res->ai_addrlen);
	
	
	printf("%d", server_fd);
	printf("%s", res->ai_addr->sa_data);
	printf("\n");
	fflush(stdout);
	
	listen(server_fd,100);

	strcpy(log, "Listening on port ");
	strcat(log, portname);
	strcat(log, "\n");
	fprintf(logfile, "%s", log);
	printf("%s", log);
	fflush(logfile);
	
	fdInfos = new std::vector<fdInfo*>();

	
	for (currUID = 1; currUID <= numWatchdogs; currUID++) {
		printf("connect loop \n");fflush(stdout);
		
		char wd [1000];
		struct sockaddr_storage sa;
		socklen_t sa_len=sizeof(sa);
		int session_fd = accept(server_fd, (struct sockaddr*)&sa, &sa_len);
		if (session_fd==-1) {
			printf("failed to accept connection \n"); return -1;fflush(stdout);
		}
	
		inet_ntop(sa.ss_family, get_in_addr((struct sockaddr *)&sa), wd, sizeof wd);
        printf("server: got connection from %s\n", wd);fflush(stdout);		fflush(stdout);
					
					
		fdInfo* newFD = new fdInfo(session_fd, currUID, wd);
		fdInfos->push_back(newFD);
		
	}
	sleep(1);
	strcpy(log, "All watchdogs connected… \n");
	fprintf(logfile, "%s", log);
	printf("%s", log);
	fflush(logfile);
	
	
	fflush(stdout);
	//Kick off threads & go to handling
	for(unsigned int i = 0; i < fdInfos->size(); i++) {
		printf(" creating thread for monitoring watchdog! fd: %d  UID: %d  \n", fdInfos->at(i)->session_fd,fdInfos->at(i)->UID );
		fflush(stdout);
		pthread_create((pthread_t*)&(fdInfos->at(i)->thread), NULL , &handle_watchdog, fdInfos->at(i));
	}
	
	
	logfileMutex.lock();
	strcpy(log, "Issuing start monitoring… \n");
	fprintf(logfile, "%s", log);
	printf("%s", log);
	fflush(logfile);
	logfileMutex.unlock();


	
	
	
	////////////////////////////////////////////////////////////
	


	
	printf(" before joins \n");
	fflush(stdout);
	for(unsigned int i = 0; i < fdInfos->size(); i++) {
		pthread_join((pthread_t)(fdInfos->at(i)->thread), NULL); // wait for the thread to exit first.
	}

	fclose(logfile);
    return 0;

}

void* handle_watchdog(void* args) {
		fdInfo* thisFD = (fdInfo*) args;
	
		logfileMutex.lock();
		strcpy(log, "Incoming watchdog connection from IP ");
		strcat(log, thisFD->host);
		strcat(log, "\n");
		fprintf(logfile, "%s", log);
		printf("%s", log);
		fflush(logfile);
		
		
		char UIDChar[100]; 
		sprintf(UIDChar, "%d", thisFD->UID);
		char info[1000];
		strcpy(info, "UID ");
		strcat(info, UIDChar);
		send(thisFD->session_fd, info, 1000, 0);
		
		
		strcpy(log, "Assigned ");
		strcat(log, UIDChar);
		strcat(log, " to watchdog at IP ");
		strcat(log, thisFD->host);
		strcat(log, "\n");
		fprintf(logfile, "%s", log);
		printf("%s", log);
		fflush(logfile);
		logfileMutex.unlock();
		
		
		char start[10] = "start";
		send(thisFD->session_fd, start, 10, 0);
		
		
		while(1) {
			char buffer[1000];
			int pack, byte, flo;
			
			if (recv(thisFD->session_fd, buffer, 1000, 0) <= 0) {
					printf(" num bytes <= 0 \n");
					fflush(stdout);
				// got error or connection closed by client
				// connection closed
				close(thisFD->session_fd);
				return NULL;
			} else {
				
				printf("from buffer:   %s \n", buffer);
				printf("\nend Buffer\n");
				fflush(stdout);
				
				
				std::string::size_type sz;  
				
				char* report = strtok (buffer," ");
				report = strtok (NULL," ");
				report = strtok (NULL," ");
				pack = std::stoi(report, &sz);
				fprintf(stdout, "%d",  pack);
				fflush(stdout);
				report = strtok (NULL," ");
				byte = std::stoi(report, &sz);
				fprintf(stdout, "%d", byte);
				fflush(stdout);
				report = strtok (NULL," ");
				flo = std::stoi(report, &sz);
				fprintf(stdout, "%d", flo);
				fflush(stdout);
				// split[0] is report
				// split[1] is report number
				
				
				
				
				fprintf(stdout, "what?  %d %d %d \n",  pack, byte, flo);
				fflush(stdout);	
					
				logfileMutex.lock();
				fprintf(logfile, "Recieved report UID %d %d %d %d \n", thisFD->UID, pack, byte, flo);
				fprintf(stdout, "Recieved report UID %d %d %d %d \n", thisFD->UID, pack, byte, flo);
				fflush(logfile);
				fflush(stdout);
				logfileMutex.unlock();
				
				totalTrafficMutex.lock();
				totalPackets += pack;
				totalBytes += byte;
				totalFlows += flo;
				numReports += 1;

				
				if(numReports == numWatchdogs) {
					logfileMutex.lock();
					fprintf(logfile, "Total Traffic %d %d %d \n", totalPackets, totalBytes, totalFlows);
					fprintf(stdout, "Total Traffic %d %d %d \n", totalPackets, totalBytes, totalFlows);
					fflush(logfile);
					fflush(stdout);			

					totalBytes = 0;
					totalFlows = 0;
					totalPackets = 0;
					numReports = 0;
					logfileMutex.unlock();
				}
				
				totalTrafficMutex.unlock();
			}
			
			
			//delete[] buffer;
		}
			
		
	return NULL;
}




