all: server client
server:
	g++ Server.cpp -o server -Wall -lnsl -lsocket -lresolv
client:
	g++ Client.cpp -o client -Wall -lnsl -lsocket -lresolv
clean:
	rm -f server client *.o *txt
	
	