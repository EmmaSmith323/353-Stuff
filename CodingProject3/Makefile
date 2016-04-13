all: watchdog desman
watchdog:
	g++ watchdog.cpp -g -o watchdog -Wall -lnsl -lresolv -lpcap
desman:
	g++ desman.cpp -g -o desman -Wall -lnsl -lresolv -lpcap
clean:
	rm -f desman watchdog *.o *txt
