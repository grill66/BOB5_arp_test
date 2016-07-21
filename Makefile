arp_test: arp_test.o
	gcc -o arp_test arp_test.o -lpcap

arp_test.o: arp_test.c
	gcc -o arp_test.o -c arp_test.c

clean:
	rm -f ./*.o 
