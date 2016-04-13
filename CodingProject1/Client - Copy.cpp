#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <ctype.h>

int main(int argc, char *argv[] ){
	int clientSocket, num_Bytes;
	char buffer[1024];
	struct sockaddr_in serverAddr;
	socklen_t addr_size;
	
	int isUDP = false;
	char USCID[32];
	sprintf(USCID, "USCID: 6554044959");
	char Name[100];
	sprintf(Name,  "Name: Emma Smith");
	int port;
	char *filename;
	char *serverIP;
		
	char *log1;
	char *log2;
	char *log3;
	

		
	if( (argc=!8) ) {
       printf("The number of arguments is incorrect, the format should be client –u –s serverIP –p portno –l logfile \n");
	   return -1;
    }
    else {
		if(strcmp(argv[1], "-u") == 0){
			isUDP = true;
		}
		serverIP = argv[3];
		port = atoi(argv[5]);
		filename = argv[7];
    }

	
	FILE *fp;
	fp = fopen(filename, "w+");	
	fprintf(fp, "testing 1 2 3 \n");
	fflush(fp);
	
	/*Create UDP socket*/
	clientSocket = socket(PF_INET, SOCK_DGRAM, 0);

	/*Configure settings in address struct*/
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(port);
	serverAddr.sin_addr.s_addr = inet_addr(serverIP);
	memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

	/*Initialize size variable to be used later on*/
	addr_size = sizeof serverAddr;
	
	
	char log[500];
		
	strcpy(log, "connecting to the server ");
	strcat(log, serverIP);
	strcat(log, " at port ");
	char portChar[100]; 
	sprintf(portChar, "%d", port);
	strcat(log, portChar);
	fprintf(fp, log);
	fprintf(fp, "\n");
	printf(log);
	printf("\n");
	fflush(fp);
	
	memset(buffer,'\0', sizeof buffer);
	strcpy(log, "connected to server hostname ");
	char host[100]; 
	sprintf(host, "%d", serverAddr.sin_port);
	strcat(log, host);
	fprintf(fp, log);
	fprintf(fp, "\n");	
	printf(log);
	memset(buffer,'\0', sizeof buffer);	
	printf("\n");
	fflush(fp);
		// clear buffer and send the USC ID to server and write to logfile
		memset(buffer,'\0', sizeof buffer);
		strcpy(buffer, USCID);
		sendto(clientSocket, buffer, num_Bytes, 0, (struct sockaddr *)&serverAddr, addr_size);
		log1 = (char *)malloc(strlen(" client Sent ") + strlen(buffer) + strlen("\n"));
		strcpy(log1, " client Sent ");
		strcat(log1, buffer);
		strcat(log1, "\n");
		fprintf(fp, log1);
		printf(log1);
		printf("\n");
		fflush(fp);
		
		
		// clear buffer and send the Name to server and write to logfile
		memset(buffer,'\0', sizeof buffer);
		strcpy(buffer, Name);
		sendto(clientSocket, buffer, num_Bytes, 0, (struct sockaddr *)&serverAddr, addr_size);
		log2 = (char *)malloc(strlen(" client Sent ") + strlen(buffer) + strlen("\n"));
		strcpy(log2, " client Sent ");
		strcat(log2, buffer);
		strcat(log2, "\n");
		fprintf(fp, log2);
		printf(log2);
		printf("\n");
		fflush(fp);
		
		
		// clear buffer and recieve the random string from the server and write to logfile
		memset(buffer,'\0', sizeof buffer);
		num_Bytes = recvfrom(clientSocket, buffer, 1024, 0, NULL, NULL);
		log3 = (char *)malloc(strlen(" client Recieved ") + strlen(buffer) + strlen("\n"));
		strcpy(log3, " client Recieved ");
		strcat(log3, buffer);
		strcat(log3, "\n");
		fprintf(fp, log3);
		printf(log3);
		printf("\n");
		fflush(fp);
		
		
		// clear buffer and send the string length to server and write to logfile
		int strLength = num_Bytes;
		memset(buffer,'\0', sizeof buffer);
		char len[100]; 
		sprintf(len, "%d", strLength);
		strcpy(buffer, len);
		sendto(clientSocket, buffer, num_Bytes, 0, (struct sockaddr *)&serverAddr, addr_size);
		log2 = (char *)malloc(strlen(" client Sent ") + strlen(buffer) + strlen("\n"));
		strcpy(log2, " client Sent ");
		strcat(log2, buffer);
		strcat(log2, "\n");
		fprintf(fp, log2);
		printf(log2);
		printf("\n");
		fflush(fp);


	fclose(fp);
	return 0;
}
