#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
/*#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>*/
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <pfring.h>
#include <malloc.h>
#include "notmine.h"

#define PORT_RANGE 65356
//#define DEF_DEV "eth0"

typedef struct portlist portlist;

void sighandler(int sig, siginfo_t *siginfo, void *context);

void packet_handler(const struct pfring_pkthdr *hdr, u_char *pkt);

void printip(uint dstip, uint srcip);

void statistics();

void listhandler(int size);

void endian(u_short *a);

int L;
pfring *handle;
FILE *f;
char dst_ip [16];
char src_ip [16];

int main(int argc, char *args[]) {

	//u_char peer[] = { /* Packet 1 */
		     /* 0x40, 0xa6, 0x77, 0x65, 0x77, 0x59, 0xc0, 0x8c, 0x60, 0x98, 0xad, 0x01, 0x81, 0x00, 0x01, 0x90,
		      0x08, 0x00, 0x45, 0x00, 0x01, 0x22, 0x0d, 0xd3, 0x40, 0x00, 0x3b, 0x06, 0xa9, 0x02, 0x0a, 0x12,
		      0x0a, 0x15, 0x0a, 0xc4, 0x69, 0x16, 0x82, 0x3b, 0x1f, 0x90, 0x5b, 0x94, 0x33, 0xd8, 0x06, 0x2c,
		      0x2d, 0x13, 0x80, 0x18, 0x01, 0xf5, 0x1f, 0x51, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x3a, 0x34,
		      0x56, 0x19, 0xfc, 0xae, 0x94, 0x1e, 0x82, 0xfe, 0x00, 0xe6, 0x0c, 0x4d, 0x9b, 0x61, 0x06, 0x53,
		      0x91, 0x6c, 0x4a, 0x22, 0xe9, 0x16, 0x6d, 0x3f, 0xff, 0x04, 0x68, 0x60, 0xdd, 0x0e, 0x7e, 0x5f,
		      0x96, 0x50, 0x3c, 0x63, 0xaa, 0x56, 0x22, 0x7c, 0xa3, 0x51, 0x22, 0x7f, 0xaa, 0x55, 0x1c, 0x49,
		      0x83, 0xe3, 0xca, 0xe2, 0x95, 0x5b, 0xb0, 0x4c, 0x91, 0x45, 0x6f, 0x7e, 0xfe, 0x52, 0x3f, 0x28,
		      0xfe, 0x07, 0x21, 0x2b, 0xac, 0x02, 0x6e, 0x60, 0xaf, 0x53, 0x3d, 0x2f, 0xb6, 0x00, 0x39, 0x2e,
		      0xae, 0x4c, 0x3c, 0x74, 0xa8, 0x55, 0x35, 0x78, 0xa2, 0x51, 0x3d, 0x29, 0xa2, 0x05, 0x1c, 0x4f,
		      0x86, 0xad, 0xb0, 0x46, 0xcd, 0x43, 0x80, 0x4c, 0x93, 0x5d, 0x1e, 0x45, 0xeb, 0x11, 0x6d, 0x3d,
		      0xeb, 0x0c, 0x63, 0x23, 0x81, 0x6c, 0x06, 0x49, 0xf8, 0x0e, 0x60, 0x22, 0x89, 0x64, 0x68, 0x2e,
		      0xfc, 0x50, 0x3e, 0x57, 0x8b, 0x6b, 0x07, 0x28, 0xf5, 0x17, 0x65, 0x3f, 0xf4, 0x0f, 0x61, 0x28,
		      0xf5, 0x15, 0x1e, 0x4c, 0xcb, 0x7b, 0x12, 0x47, 0x9f, 0x09, 0x63, 0x3e, 0xef, 0x73, 0x1a, 0x29,
		      0xf8, 0x06, 0x3d, 0x7f, 0xf3, 0x04, 0x7e, 0x20, 0xfe, 0x12, 0x62, 0x22, 0xff, 0x04, 0x7b, 0x28,
		      0xf9, 0x52, 0x39, 0x78, 0xab, 0x7b, 0x19, 0x47, 0x9f, 0x11, 0x63, 0x22, 0xf7, 0x73, 0x01, 0x25,
		      0xfe, 0x13, 0x61, 0x28, 0xe8, 0x0f, 0x63, 0x29, 0xfe, 0x16, 0x69, 0x2f, 0x81, 0x6a, 0x06, 0x4b,
		      0xe8, 0x15, 0x6d, 0x39, 0xee, 0x12, 0x1e, 0x4c, 0xab, 0x43, 0x15, 0x47, 0x97, 0x13, 0x63, 0x22,
		      0xef, 0x35, 0x74, 0x23, 0xd8, 0x0e, 0x79, 0x23, 0xef, 0x71, 0x08, 0x55, 0x99, 0x43, 0x09, 0x5d,
		      0x2d, 0x84, 0xd8, 0x4c};*/
	char fppath [150];//file path
	char *dev;
	u_short *p;
	u_short p1;
	u_short p2;
	u_char *buffer = NULL;
	char *filter = "tcp or udp";
	dev = DEF_DEV;
	struct sigaction act;
	struct pfring_pkthdr hdr;
	memset (&act, '\0', sizeof(act));
	sprintf(fppath, "%s.csv", DEF_F);
	/* Use the sa_sigaction field because the handles has two additional parameters */
	act.sa_sigaction = &sighandler;
	/* The SA_SIGINFO flag tells sigaction() to use the sa_sigaction field, not sa_handler. */
	act.sa_flags = SA_SIGINFO;
	sigaction(SIGINT, &act, NULL);
	if (argc == 3)
	{
		dev = args[1];
		sprintf(fppath, "%s.csv", args[2]);
	}
	printf("selected device is: %s\n", dev);

	f = fopen(fppath, "w");
	if (f == NULL)
	{
		printf("error opening file: %s", strerror(errno));
	}
	handle = pfring_open(dev, 512, PF_RING_PROMISC);
	if (handle == NULL) {
		printf("couldn't open device: %s\n", dev);
		return 2;
	}
	pfring_enable_ring(handle);
	pfring_set_bpf_filter(handle, filter);
	printf("finsihed setting up device\n");
	fprintf(f, "%s", "proto,dst port,dst ip,dst mac,src port,src ip,src mac,packet size\n");
	while (1)
	{
		pfring_recv(handle, &buffer, 0, &hdr, 1);
		p = (u_short *)(buffer+12);
		p1 = *p;
		p2 = *(p+2);
		endian(&p1);
		endian(&p2);
		if(p1 == 0x0800 || (p1 == 0x8100 && p2 == 0x0800))
		{
			packet_handler(&hdr ,buffer);
		} 
	}
	//pfring_recv(handle, &buffer, 0, &hdr, 1);
	//packet_handler(&hdr, peer);
	return 0;

}


void packet_handler(const struct pfring_pkthdr *hdr, u_char *pkt) {
	/* Only looking for ports and ips so no need to seperate udp from tcp */

	struct ethernet_hdr *ethernet = NULL; /* The ethernet header */
	struct ip_hdr *ip = NULL; /* The IP header */
	struct tcp_hdr *tcp = NULL; /* The TCP header */
	char str [150];
	u_int size_ip;
	u_int size_tcp;
	ethernet = (struct ethernet_hdr*) (pkt);
	endian(&(ethernet->ether_type));
	if (ethernet->ether_type == 0x8100)
	{
		//printf("vlan!!!\n");
		ip = (struct ip_hdr*) (pkt + 14 + 4);
	}
	else
		ip = (struct ip_hdr*) (pkt + 14);
	size_ip = IP_HL(ip) * 4;
	if (size_ip < 20) {
		printf("* Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	tcp = (struct tcp_hdr*) (pkt + 14 + size_ip);
	//size_tcp = TH_OFF(tcp) * 4;
	//printf("src port: %d, dst port: %d\n", tcp->th_sport, tcp->th_dport);
	endian(&(tcp->th_dport));
	endian(&(tcp->th_sport));
	//printf("src port: %d, dst port: %d, src ip: %s, dst ip: %s\n", tcp->th_sport, tcp->th_dport, inet_ntoa(*(struct in_addr *)&ip->ip_src), inet_ntoa(*(struct in_addr *)&ip->ip_dst));
	printip(ip->ip_dst, ip->ip_src);
	sprintf(str, "%d,%d,%s,%02x:%02x:%02x:%02x:%02x:%02x,%d,%s,%02x:%02x:%02x:%02x:%02x:%02x,%d\n",
			ip->ip_p,
			tcp->th_dport,
			dst_ip,
			ethernet->ether_dhost[0],
			ethernet->ether_dhost[1],
			ethernet->ether_dhost[2],
			ethernet->ether_dhost[3],
			ethernet->ether_dhost[4],
			ethernet->ether_dhost[5],
			tcp->th_sport,
			src_ip,
			ethernet->ether_shost[0],
			ethernet->ether_shost[1],
			ethernet->ether_shost[2],
			ethernet->ether_shost[3],
			ethernet->ether_shost[4],
			ethernet->ether_shost[5],
			hdr->len);

	fprintf(f, "%s", str);
	listhandler(strlen(str));

}

void printip(uint dstip, uint srcip)
{
	int first, second, third, fourth;
	fourth = dstip % 256;
	dstip /= 256;
	third = dstip % 256;
	dstip /= 256;
	second = dstip % 256;
	dstip /= 256;
	first = dstip % 256;
	sprintf(dst_ip,"%d.%d.%d.%d", fourth, third, second, first);
	fourth = srcip % 256;
	srcip /= 256;
	third = srcip % 256;
	srcip /= 256;
	second = srcip % 256;
	srcip /= 256;
	first = srcip % 256;
	sprintf(src_ip, "%d.%d.%d.%d", fourth, third, second, first);

}

void endian(u_short *a) {

	/*change from one endian form to the other for u_short type*/
	char *c1 = (char*)a;
	char *c2 = c1+1;
	char c = *c1;
	*c1 = *c2;
	*c2 = c;

}

void statistics() {

	/*int cnt = 0, max = 0;
	int i = 0;
	u_short maxp;
	do {
		if (max < L[i]) {
			max = L[i];
			maxp = i;
		}
		cnt += L[i];
		i++;
	} while (i < PORT_RANGE);
	printf(
			"\nthe most used port is %d with %d packets linked to it out of %d packets in total\n",
			maxp, max, cnt / 2);*/

}

void listhandler(int size) {

	L += size;
	if (L >= 200000000)
	{
		sighandler(2, NULL, NULL);
	}

}

void sighandler(int sig, siginfo_t *siginfo, void *context) {

	//int i = 0;
	pfring_close(handle);
	//statistics();
	/*for (; i < PORT_RANGE; i++)
	{
		if(L[i] > 0)
		printf("port: %d with %d packets linked to it\n", i,L[i]);
	}*/
	fclose(f);
	exit(1);

}
