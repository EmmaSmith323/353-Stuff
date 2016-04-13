all: balancer test
balancer:
	g++ balancer.cpp -o balancer -Wall -lnsl -lresolv -lpcap
test:
	g++ test.cpp -o test -Wall -lnsl -lresolv -lpcap
clean:
	rm -f balancer test *.o *txt
	
	