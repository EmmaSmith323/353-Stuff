all: watchdog desman
watchdog:
	g++ watchdog.cpp -g -o watchdog -Wall -lnsl -lresolv -lpcap -lpthread  -std=c++0x
desman:
	g++ desman.cpp -g -o desman -Wall -lnsl -lresolv -lpcap -lpthread  -std=c++0x
clean:
	rm -f desman watchdog *.o *txt
