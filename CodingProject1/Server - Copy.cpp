#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>


int main( int argc, char *argv[] ){
	int udpSocket, num_Bytes;
	char buffer[1024];
	struct sockaddr_in serverAddr;
	struct sockaddr_storage clientAddr;
	socklen_t addr_size;
	bool isUDP = false;
	char log[500];
	
	int port;
	char *filename; 
	
	 printf("eat");
	if( (argc=!6) ) {
       printf("The number of arguments is incorrect, the format should be server –u –p portno –l logfile");
	   return -1;
    }
    else {
		if(strcmp(argv[1], "-u") == 0){
			isUDP = true;
		}
		port = atoi(argv[3]);
		filename = argv[5];
    }
	 printf("shit");
	//open logfile
	FILE *fp;	
	fp = fopen(filename, "w+");
	fprintf(fp, "testing 1 2 3");
	fprintf(fp, "\n");
	fflush(fp);
  
  

	/*Create UDP socket*/
	udpSocket = socket(PF_INET, SOCK_DGRAM, 0);

	/*Configure settings in address struct*/
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(port);
	serverAddr.sin_addr.s_addr = inet_addr("68.181.201.255");
	memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

	/*Bind socket with address struct*/
	bind(udpSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr));

	/*Initialize size variable to be used later on*/
	addr_size = sizeof clientAddr;
	
	fflush(fp);
	
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
	memset(buffer,'\0', sizeof buffer);
	fflush(fp);
	
	int i;
	char *log1;
	char *log2;
	char *log3;
	//Wait for messages
		memset(buffer,'\0', sizeof buffer);
	fprintf(fp, "waiting for message \n");
	fflush(fp);
		// clear buffer and recieve the USC ID from client

		num_Bytes = recvfrom(udpSocket, buffer, 1024, 0, (struct sockaddr *)&clientAddr, &addr_size);
		
	fprintf(fp, "recieved message \n");
	fflush(fp);
		

	strcpy(log, "received client connection from hostname ");
	//char hostaddrChar[100]; 
	//sprintf(hostaddrChar, "%s", inet_ntoa(((struct sockaddr_in )clientAddr).sin_addr));
	//strcat(log, hostaddrChar);

	
	//int Cport = ((struct sockaddr_in )clientAddr).sin_port;
	//char CportChar[100]; 
	//sprintf(CportChar, "%d", Cport);
	//strcat(log, CportChar);
	fprintf(fp, log);	
	printf(log);
	memset(buffer,'\0', sizeof buffer);	


		
		// write to logfile
		log1 = (char *)malloc(strlen(" server Recieved ") + strlen(buffer) + strlen("\n"));
		strcpy(log1, " server Recieved ");
		strcat(log1, buffer);
		strcat(log1, "\n");
		fprintf(fp, log1);
		printf(log1);
		fflush(fp);
		
		
		// clear buffer and reviece the Name from client
  		memset(buffer,'\0', sizeof buffer);
		num_Bytes = recvfrom(udpSocket, buffer, 1024, 0, (struct sockaddr *)&clientAddr, &addr_size);
		// write to logfile
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
		// send random string back to client and write to logfile
		sendto(udpSocket, buffer, num_Bytes, 0, (struct sockaddr *)&clientAddr, addr_size);
		log3 = (char *)malloc(strlen(" server Sent ") + strlen(buffer) + strlen("\n"));
		strcpy(log3, " server Sent ");
		strcat(log3, buffer);
		strcat(log3, "\n");
		fprintf(fp, log3);
		printf(log3);
		memset(buffer,'\0', sizeof buffer);
	
	
		// clear buffer and reviece the string length from client
  		memset(buffer,'\0', sizeof buffer);
		num_Bytes = recvfrom(udpSocket, buffer, 1024, 0, (struct sockaddr *)&clientAddr, &addr_size);
		// write to logfile
		log2 = (char *)malloc(strlen(" server Recieved ") + strlen(buffer) + strlen("\n"));
		strcpy(log2, " server Recieved ");
		strcat(log2, buffer);
		strcat(log2, "\n");
		fprintf(fp, log2);
		printf(log2);
		fflush(fp);
		
	
	
	
	printf("terminating server…");	
	fflush(fp);
	
	
	//close logfile
	fclose(fp);
	return 0;
}
