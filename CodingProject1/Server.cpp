#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <unistd.h>
#include <pcap.h>


	//global vars
	bool isUDP;
	bool isPart3 = false;
	int port;
	char *logFilename; 
	char *imgFilename;
	char *path;
	
	void serverUDP();
	void serverPart2();
	void serverPart3();
	
int main( int argc, char *argv[] ){

	if(argc == 1) {
		printf("Usage: Part 1. server –u –p portno –l logfile /n /t Part 2.  server –t –p portno –l logfile –I imagefile \n \t Part 3.  server –t –p portno –l logfile –d <path>");
		return -1;
	}
	for (int i = 1; i < argc; i++)
	{
		if(strcmp(argv[i],"-u") == 0) {
			isUDP = true;
		}
		else if(strcmp(argv[i],"-t") == 0) {
			isUDP = false;
		}
		else if(strcmp(argv[i],"-p") == 0) {
			port = atoi(argv[i+1]);
		}
		else if(strcmp(argv[i],"-l") == 0) {
			logFilename = argv[i+1];
		}
		else if(strcmp(argv[i],"-i") == 0) {
			imgFilename = argv[i+1];
		}
		else if(strcmp(argv[i],"-d") == 0) {
			path = argv[i+1];
			isPart3 = true;
		}
	}
	
	if(isUDP) {
		//Part1
		printf("Starting part 1 \n");
		serverUDP();
	}
	else if(!isPart3){
		printf("Starting part 2 \n");
		//Part2
		serverPart2();
	}
	else {
		printf("Starting part 3 \n");
		//Part3
		serverPart3();
	}
		


	

	
	return 0;
}


void serverUDP() {
	//necessary variable declarations
	int udpSocket, num_Bytes;
	char buffer[1000];
	struct sockaddr_in serverAddr;
	struct sockaddr_storage clientStorage;
	socklen_t addr_size;
	addr_size = sizeof clientStorage;
	int i;
	char *log1;
	char *log2;
	char *log3;
	char log[1000];
	
	//open logfile
	FILE *fp;	
	fp = fopen(logFilename, "w+");
  
	// create udp socket, DGRAM b/c UDP
	udpSocket = socket(PF_INET, SOCK_DGRAM, 0);

	//configure settings --- TODO: figure out how to get IP address?
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(port);
	serverAddr.sin_addr.s_addr = inet_addr("68.181.201.255");
	memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

	//bind socket
	bind(udpSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr));

	// First log, starting  server notice.
	strcpy(log, "server started on ");
	char *ip_addr = inet_ntoa(serverAddr.sin_addr);
	strcat(log, ip_addr);
	strcat(log, " at port ");
	char portChar[100]; 
	sprintf(portChar, "%d", port);
	strcat(log, portChar);
	fprintf(fp, log);
	fprintf(fp, "\n");
	printf(log);
	printf("\n");
	memset(buffer,'\0', sizeof buffer);
	fflush(fp);
	
	// clear buffer and recieve the USC ID from client
	memset(buffer,'\0', sizeof buffer);
	num_Bytes = recvfrom(udpSocket, buffer, 1024, 0, (struct sockaddr *)&clientStorage, &addr_size);
	char ID[50];
	strcpy(ID, buffer);

	//Second log, the client info
	char host[500];
	getnameinfo((struct sockaddr *)&clientStorage, addr_size, host, sizeof(host), NULL, 0, 0);	
	strcpy(log, "received client connection from hostname ");
	strcat(log, host);
	strcat(log, " port ");
	strcat(log, portChar);
	fprintf(fp, log);	
	fprintf(fp, "\n");
	printf(log);
	memset(buffer,'\0', sizeof buffer);	
		
	// write USCID to logfile
	log1 = (char *)malloc(strlen(" server Recieved ") + strlen(ID) + strlen("\n"));
	strcpy(log1, " server Recieved ");
	strcat(log1, ID);
	strcat(log1, "\n");
	fprintf(fp, log1);
	printf(log1);
	fflush(fp);
	
	// clear buffer and reviece the Name from client
	memset(buffer,'\0', sizeof buffer);
	num_Bytes = recvfrom(udpSocket, buffer, 1024, 0, (struct sockaddr *)&clientStorage, &addr_size);
	// write name to logfile
	log2 = (char *)malloc(strlen(" server Recieved ") + strlen(buffer) + strlen("\n"));
	strcpy(log2, " server Recieved ");
	strcat(log2, buffer);
	strcat(log2, "\n");
	fprintf(fp, log2);
	printf(log2);
	fflush(fp);
	
	// clear buffer and fill with random string
	memset(buffer,'\0', sizeof buffer);
	num_Bytes = rand()%(250+ (1-100))+100;
	for(i = 0; i < num_Bytes-1; i++) {
		buffer[i] = 'A' + (random() % 26);
	}
	// send message to client and write to logfile
	num_Bytes = sizeof buffer;
	sendto(udpSocket, buffer, num_Bytes, 0, (struct sockaddr *)&clientStorage, addr_size);
	log3 = (char *)malloc(strlen(" server Sent ") + strlen(buffer) + strlen("\n"));
	strcpy(log3, " server Sent ");
	strcat(log3, buffer);
	strcat(log3, "\n");
	fprintf(fp, log3);
	printf(log3);
	memset(buffer,'\0', sizeof buffer);

	// clear buffer and reviece the string length from client
	memset(buffer,'\0', sizeof buffer);
	num_Bytes = recvfrom(udpSocket, buffer, 1024, 0, (struct sockaddr *)&clientStorage, &addr_size);
	// write to logfile
	log2 = (char *)malloc(strlen(" server Recieved ") + strlen(buffer) + strlen("\n"));
	strcpy(log2, " server Recieved ");
	strcat(log2, buffer);
	strcat(log2, "\n");
	fprintf(fp, log2);
	printf(log2);
	fflush(fp);

	//log terminate
	fprintf(fp, "terminating server.... \n");
	printf("terminating server…");	
	fflush(fp);
	
	//close logfile
	fclose(fp);
	return;
}

void serverPart2(){
  int num_Bytes;
  char log[1000];
  int tcpSocket, clientSocket;
  char buffer[1000];
  struct sockaddr_in serverAddr;
  struct sockaddr_storage clientStorage;
  socklen_t addr_size;
  addr_size = sizeof clientStorage;
  
  //open logfile
	FILE *fp;	
	fp = fopen(logFilename, "w+");
  printf("logfile opened \n");
  //Create socket, stream b/c tcp
  tcpSocket = socket(PF_INET, SOCK_STREAM, 0);

  //configure settings --- TODO: figure out how to get IP address?
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_port = htons(port);
  serverAddr.sin_addr.s_addr = inet_addr("68.181.201.255");
  memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);  

  //bind the socket
  bind(tcpSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr));
  
  // First log, starting  server notice.
	strcpy(log, "server started on ");
	char *ip_addr = inet_ntoa(serverAddr.sin_addr);
	strcat(log, ip_addr);
	strcat(log, " at port ");
	char portChar[100]; 
	sprintf(portChar, "%d", port);
	strcat(log, portChar);
	fprintf(fp, log);
	fprintf(fp, "\n");
	printf(log);
	printf("\n");
	memset(buffer,'\0', sizeof buffer);
	fflush(fp);
	
	printf("listening \n");
  //listen, only for one in this part
  listen(tcpSocket,10);
  printf("listening 2 \n");
  //new socket for the client interaction
  clientSocket = accept(tcpSocket, (struct sockaddr *) &clientStorage, &addr_size);
printf("waiting \n");

  // second log, connected and client info
	char host[500];
	getnameinfo((struct sockaddr *)&clientStorage, addr_size, host, sizeof(host), NULL, 0, 0);	
	strcpy(log, "received client connection from hostname ");
	strcat(log, host);
	strcat(log, " port ");
	strcat(log, portChar);
	fprintf(fp, log);	
	fprintf(fp, "\n");
	printf(log);
	memset(buffer,'\0', sizeof buffer);	


	//recieve in the USCID
    memset(buffer,'\0', sizeof buffer);
	num_Bytes = recv(clientSocket, buffer, 1000, 0);
	char ID[50];
	strcpy(ID, buffer);
	//Print to log USCID
	memset(log,'\0', sizeof log);
	strcpy(log, "Server recieved ");
	strcat(log, ID);
	strcat(log, "\n");
	fprintf(fp, log);
	printf(log);
	fflush(fp);

	//recieve in the name
    memset(buffer,'\0', sizeof buffer);
	num_Bytes = recv(clientSocket, buffer, 1000, 0);
	char name[50];
	strcpy(name, buffer);
	//Print to log name
	memset(log,'\0', sizeof log);
	strcpy(log, "Server recieved ");
	strcat(log, name);
	strcat(log, "\n");
	fprintf(fp, log);
	printf(log);
	fflush(fp);
	
	//Open the file and get the image size
	FILE * imgFile = fopen(imgFilename, "rb");
	fseek(imgFile, 0, SEEK_END);
	int imgSize = ftell(imgFile);
	fseek(imgFile, 0, SEEK_END);
	//read in the image to the buffer.
	char *imgBuffer[200000];
	memset(imgBuffer,'\0', sizeof imgBuffer);
	fread(imgBuffer, 1, imgSize, imgFile);
	
	//log to file sending
	memset(log,'\0', sizeof log);
	strcpy(log, "Server sending image file ");
	strcat(log, imgFilename);
	strcat(log, "\n");
	fprintf(fp, log);
	printf(log);
	fflush(fp);
	
	//send
	send(clientSocket, imgBuffer, imgSize, 0); 
	
	
	//log terminate
	memset(log,'\0', sizeof log);
	fprintf(fp, "terminating server.... \n");
	printf("terminating server…");	
	fflush(fp);
	
	//close logfile
	fclose(fp);
	return;
}


void serverPart3() {

	int globalUID = 0;
  int num_Bytes;
  char log[1000];
  int tcpSocket, clientSocket;
  char buffer[1000];
  struct sockaddr_in serverAddr;
  struct sockaddr_storage clientStorage;
  socklen_t addr_size;
  addr_size = sizeof clientStorage;
  
  //open logfile
	FILE *fp;	
	fp = fopen(logFilename, "w+");
  printf("logfile opened \n");
  //Create socket, stream b/c tcp
  tcpSocket = socket(PF_INET, SOCK_STREAM, 0);

  //configure settings --- TODO: figure out how to get IP address?
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_port = htons(port);
  serverAddr.sin_addr.s_addr = inet_addr("68.181.201.255");
  memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);  

  //bind the socket
  bind(tcpSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr));
  
  // First log, starting  server notice.
	strcpy(log, "server started on ");
	char *ip_addr = inet_ntoa(serverAddr.sin_addr);
	strcat(log, ip_addr);
	strcat(log, " at port ");
	char portChar[100]; 
	sprintf(portChar, "%d", port);
	strcat(log, portChar);
	fprintf(fp, log);
	fprintf(fp, "\n");
	printf(log);
	printf("\n");
	memset(buffer,'\0', sizeof buffer);
	fflush(fp);
	
	//listen, only for one in this part
	listen(tcpSocket,10);
	
	//loop and keep accepting connections
  while(1){
    clientSocket = accept(tcpSocket, (struct sockaddr *) &clientStorage, &addr_size);
    //fork off to handle
    if(!fork()){
      num_Bytes = 1;
      //while still connected
      while(num_Bytes!=0){
         // second log, connected and client info
		 int thisUID = globalUID;
		 globalUID++;
		char host[500];
		getnameinfo((struct sockaddr *)&clientStorage, addr_size, host, sizeof(host), NULL, 0, 0);	
		strcpy(log, "received client connection ");
		char thisUIDChar[100]; 
		sprintf(thisUIDChar, "%d", thisUID);
		strcpy(log, thisUIDChar);
		strcpy(log, " from hostname ");
		strcat(log, host);
		strcat(log, " port ");
		strcat(log, portChar);
		fprintf(fp, log);	
		fprintf(fp, "\n");
		printf(log);
		memset(buffer,'\0', sizeof buffer);	

		//recieve in the USCID
		memset(buffer,'\0', sizeof buffer);
		num_Bytes = recv(clientSocket, buffer, 1000, 0);
		char ID[50];
		strcpy(ID, buffer);
		//Print to log USCID
		memset(log,'\0', sizeof log);
		strcpy(log, thisUIDChar);
		strcpy(log, " Server recieved ");
		strcat(log, ID);
		strcat(log, "\n");
		fprintf(fp, log);
		printf(log);
		fflush(fp);

		//recieve in the name
		memset(buffer,'\0', sizeof buffer);
		num_Bytes = recv(clientSocket, buffer, 1000, 0);
		char name[50];
		strcpy(name, buffer);
		//Print to log name
		memset(log,'\0', sizeof log);
		strcpy(log, thisUIDChar);
		strcpy(log, " Server recieved ");
		strcat(log, name);
		strcat(log, "\n");
		fprintf(fp, log);
		printf(log);
		fflush(fp);
		
		//Open the file and get the image size
		FILE * imgFile = fopen(imgFilename, "rb");
		fseek(imgFile, 0, SEEK_END);
		int imgSize = ftell(imgFile);
		fseek(imgFile, 0, SEEK_END);
		//read in the image to the buffer.
		char *imgBuffer[200000];
		memset(imgBuffer,'\0', sizeof imgBuffer);
		fread(imgBuffer, 1, imgSize, imgFile);
		
		//log to file sending
		memset(log,'\0', sizeof log);
		strcpy(log, thisUIDChar);
		strcpy(log, " Server sending image file ");
		strcat(log, imgFilename);
		strcat(log, "\n");
		fprintf(fp, log);
		printf(log);
		fflush(fp);
		
		//send
		send(clientSocket, imgBuffer, imgSize, 0); 
	
      }
      close(clientSocket);
	  strcpy(log, " terminating client connection…  ");
	  fprintf(fp, log);
	  fflush(fp);
	  
      exit(0);
    }
    /*if parent, close the socket and go back to listening new requests*/
    else{
      close(clientSocket);
	  strcpy(log, " terminating client connection…  ");
	  fprintf(fp, log);
	  fflush(fp);
    }
  }
	
	
}
 

	

