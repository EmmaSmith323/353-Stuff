#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <ctype.h>

	int isUDP = false;
	int port;
	char *logFilename; 
	char *imgFilename;
	char *path;
	char *serverIP;
		
	void clientUDP();
	void clientPart2and3();

int main(int argc, char *argv[] ){

	if(argc == 1) {
		printf("Usage: Part 1.  client –u –s serverIP –p portno –l logfile /n /t Part 2.   client –t –s serverIP –p portno –l logfile –I imagefile \n \t Part 3.  client –t –s serverIP –p portno –l logfile –I imagefile");
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
		else if(strcmp(argv[i],"-s") == 0) {
			serverIP = argv[i+1];
		}
		else if(strcmp(argv[i],"-l") == 0) {
			logFilename = argv[i+1];
		}
		else if(strcmp(argv[i],"-i") == 0) {
			imgFilename = argv[i+1];
		}

	}
	
	if(isUDP) {
		//Part1
		printf("Starting part 1 \n");
		clientUDP();
	}
	else {
		//Part 2 or 3, they are the same from the client persepctive
		printf("Starting part 2 or 3 \n");
		clientPart2and3();
	}
	
	
	return 0;
}


void clientUDP() {
	// initialize necessary variables
	int clientSocket, num_Bytes;
	char buffer[1024];
	struct sockaddr_in serverAddr;
	socklen_t addr_size;
	addr_size = sizeof serverAddr;
	char *log1;
	char *log2;
	char *log3;
	char USCID[32];
	sprintf(USCID, "USCID: 6554044959");
	char Name[100];
	sprintf(Name,  "Name: Emma Smith");
	char log[1000];
	
	//open logfile
	FILE *fp;
	fp = fopen(logFilename, "w+");	
	
	//create udp socket
	clientSocket = socket(PF_INET, SOCK_DGRAM, 0);

	//configure settings
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(port);
	serverAddr.sin_addr.s_addr = inet_addr(serverIP);
	memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);
		
	//first log, connection
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
	
	//clear buffer and log the server info
	memset(buffer,'\0', sizeof buffer);
	strcpy(log, "connected to server hostname ");
	strcat(log, serverIP); 
	fprintf(fp, log);
	fprintf(fp, "\n");	
	printf(log);
	memset(buffer,'\0', sizeof buffer);	
	printf("\n");
	fflush(fp);
	
	// clear buffer and send the USC ID to server and write to logfile
	memset(buffer,'\0', sizeof buffer);
	strcpy(buffer, USCID);
	num_Bytes = sizeof buffer;
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
	num_Bytes = sizeof buffer;
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
	int strLength = strlen(buffer);
	memset(buffer,'\0', sizeof buffer);
	char len[100]; 
	sprintf(len, "%d", strLength);
	strcpy(buffer, "string length: ");
	strcat(buffer, len);
	num_Bytes = sizeof buffer;
	sendto(clientSocket, buffer, num_Bytes, 0, (struct sockaddr *)&serverAddr, addr_size);
	log2 = (char *)malloc(strlen(" client Sent ") + strlen(buffer) + strlen("\n"));
	strcpy(log2, " client Sent ");
	strcat(log2, buffer);
	strcat(log2, "\n");
	fprintf(fp, log2);
	printf(log2);
	printf("\n");
	fflush(fp);

	//log terminate and close
	fprintf(fp, "terminating client.... \n");
	printf("terminating client....");	
	fflush(fp);
	fclose(fp);
	return;
}


void clientPart2and3() {
	// initialize necessary variables
	int clientSocket, num_Bytes;
	char buffer[1000];
	struct sockaddr_in serverAddr;
	socklen_t addr_size;
	addr_size = sizeof serverAddr;
	char USCID[32];
	sprintf(USCID, "USCID: 6554044959");
	char Name[100];
	sprintf(Name,  "Name: Emma Smith");
	char log[1000];
	
	//open logfile
	FILE *fp;
	fp = fopen(logFilename, "w+");	
	printf("logfile opened \n");
	//create socket, stream b/c tcp
	clientSocket = socket(PF_INET, SOCK_STREAM, 0);

	//configure settings
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(port);
	serverAddr.sin_addr.s_addr = inet_addr(serverIP);
	memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);
	
	//make connection
	int ret = connect(clientSocket,(struct sockaddr *) &serverAddr, addr_size);	
	printf("connect ");
		fprintf(fp, "DEBUG connect ");
		char retChar[100]; 
		sprintf(retChar, "%d", ret);
		printf(retChar);
		fprintf(fp, retChar);
	printf("\n");
		fprintf(fp, "\n");
		fflush(fp);
		
	//first log, connection
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
	
	//clear buffer and log the server info
	memset(buffer,'\0', sizeof buffer);
	strcpy(log, "connected to server hostname ");
	strcat(log, serverIP);   
	fprintf(fp, log);
	fprintf(fp, "\n");	
	printf(log);
	memset(buffer,'\0', sizeof buffer);	
	printf("\n");
	fflush(fp);
	
	// clear buffer and send the USC ID to server
	memset(buffer,'\0', sizeof buffer);
	strcpy(buffer, USCID);
	num_Bytes = sizeof buffer;
	printf("before send \n");
	send(clientSocket, buffer, num_Bytes, 0);
		printf("after send \n");
	// write to logfile
	memset(log,'\0', sizeof log);
	strcpy(log, "Client Sent ");
	strcat(log, buffer);
	strcat(log, "\n");
	fprintf(fp, log);
	printf(log);
	printf("\n");
	fflush(fp);
	
	// clear buffer and send the Name to server
	memset(buffer,'\0', sizeof buffer);
	strcpy(buffer, Name);
	num_Bytes = sizeof buffer;
	send(clientSocket, buffer, num_Bytes, 0);
	// write to logfile
	memset(log,'\0', sizeof log);
	strcpy(log, "Client Sent ");
	strcat(log, buffer);
	strcat(log, "\n");
	fprintf(fp, log);
	printf(log);
	printf("\n");
	fflush(fp);
	
	// clear buffer and recieve the image
	memset(buffer,'\0', sizeof buffer);
	num_Bytes = recv(clientSocket, buffer, sizeof buffer, 0);
		
	//SAVE IMAGE
	FILE *imgF;	
	imgF = fopen(imgFilename, "w+");
	fwrite(buffer, 1, num_Bytes, imgF);
	
	// write to logfile
	memset(log,'\0', sizeof log);
	strcpy(log, "Client Recieved image and saved as ");
	strcat(log, imgFilename);
	strcat(log, "\n");
	fflush(fp);


	//log terminate and close
	fprintf(fp, "terminating client.... \n");
	printf("terminating client....");	
	fflush(fp);
	fclose(fp);
	return;
}

