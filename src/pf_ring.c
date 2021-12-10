#include "sniffer.h"


pfring *handle;                                                                 // the pfring handler 
typedef struct portlist portlist;                                               // list of ports 


/**
* starting the sniffer
* param def: the device to sniff e.g. 'eth0'
* param filter: the filter of sniffing e.g. 'tcp and udp'
*/
void start_binding(char* dev, char* filter)
{
	printf("starting binder");
	unsigned short *p, p1, p2;
	struct pfring_pkthdr hdr;                                                   // packet header struct 
	unsigned char* buffer = NULL;                                               // buffer 
	handle = pfring_open(dev, 512, PF_RING_PROMISC);                            // creating pfring object

	if (handle == NULL)                                                         // if there is a problem with the device the 'handle' will be NULL
	{
		printf("error binding device %s \n", dev);
		exit(0);                                                                // stopping and exiting the function 
	}

	pfring_enable_ring(handle);                                                 // enabling pfring
	pfring_set_bpf_filter(handle, filter);                                      // setting filter 

	writeLog("\nfinished setting up device\n");
	while (1)                                                                   // running always 
	{
		pfring_recv(handle, &buffer, 0, &hdr, 1);                               // recieving a packet from the karenel mode 
		writeLog("Recieved...\n");
		p = (unsigned short *)(buffer + 12);                                    // the first char of type (header)
		p1 = *p;                                                                // the first char of proto type 
		p2 = *(p + 2);                         									// the third char of type (header) 
		endian(&p1);                                                            // converting to little endian                 
		endian(&p2);                                                            // converting to little endian ( if its a VLAN )
		if (p1 == 0x0800 || (p1 == 0x8100 && p2 == 0x0800))                     // if it's ethernet then p1 will be 0x0800 , else if it's Vlan p1 will be 0x8100 and p2 will be 0x0800
		{
			packet_handler(&hdr, buffer);                                       // calling the packet handler , pointer to the packet , and the buffer that contains the packet 
		}
	}
}


/**
* converting little endian to big endian and big endian to little
* param unsigned short a: pointer to the address to swap endian
*/
void endian(unsigned short *a)
{
	char *c1 = (char*)a;                                                        // *c1 = *a 
	char *c2 = c1 + 1;                                                          // *c2 = *(a + 1)
	char c = *c1;                                                               // *c = *a
	*c1 = *c2;                                                                  // *a = *(a+1)
	*c2 = c;                                                                    // *(a+1) = *a
}


/**
* the packet hendler
* param *hdr: the header of the packet
* param *pkt: the whole packet data
*/
void packet_handler(const struct pfring_pkthdr *hdr, unsigned char* pkt)
{
	char s_ip[16], d_ip[16];
	int s_port, d_port;
	struct ethernet_hdr *eth_hdr = NULL;                                        // ethernet header 
	struct ip_hdr *ip = NULL;                                                   // ip header 
	struct tcp_hdr *tcp = NULL;                                                 // potential tcp header 
	struct udp_hdr *udp = NULL;                                                 // potential udp header         
	char str[150];
	unsigned int size_ip = 0;                                                   // size of ip header 
	unsigned int size_tcp_udp = 0;                                              // size of tcp/udp header                 
	unsigned int size_data = 0;                                                 // data size of the packet ( UDP or TCP data ) 

	eth_hdr = (struct ethernet_hdr*) (pkt);                                     // the ethernet header ( DATA LINK )
	endian(&(eth_hdr->ether_type));                                             // getting type ( converting to little endian )
	if (eth_hdr->ether_type == 0x8100)
	{                                                       // its a Vlan (header is 18 bytes , not 14)
		ip = (struct ip_hdr*)(pkt + 14 + 4);
	}
	else
	{
		ip = (struct ip_hdr*)(pkt + 14);                                        // eth header 
	}
	size_ip = IP_HL(ip) * 4;                                                    // ip header size 
	if (size_ip < 20)
	{
		writeLog(" wrong IP header length \n");                                     // minimum of the IP header is 20 bytes 
		exit(1);                                                                // stopping the program 
	}
	convert_ip(ip->ip_src, s_ip);                                              // src ip  ****** check this lines, not sure if works !
	convert_ip(ip->ip_dst, d_ip);                                              // dst ip 	
	endian(&(ip->ip_len));
	if (ip->ip_p == 0x06)                                                       // tcp protocol                 
	{
		tcp = (struct tcp_hdr*)(pkt + 14 + size_ip);                            // getting tcp header 
		endian(&(tcp->th_dport));                                               // converting dst port to little endian 
		endian(&(tcp->th_sport));                                               // converting src port to little endian 
		d_port = (int)tcp->th_dport;                                            // saving ports as int 
		s_port = (int)tcp->th_sport;                                            // saving ports as int 
		size_tcp_udp = TH_OFF(tcp) * 4;                                         // getting tcp header lenght ( data offset * 4 )
		size_data = (int)ip->ip_len - size_tcp_udp - size_ip;                   // getting the length of the data in the packet		
		insert(s_port,d_port,s_ip,d_ip, size_data,"tcp");
	}
	else if (ip->ip_p == 0x11)                                                  // udp protocol
	{
		udp = (struct udp_hdr*)(pkt + 14 + size_ip);                            // getting the udp header 
		d_port = (int)udp->uh_dport;                                            // converting dst port to little endian 
		s_port = (int)udp->uh_sport;                                            // converting src port to little endian 
		size_tcp_udp = 8;                                                       // the size of udp header is always 8 bytes 
		size_data = ip->ip_len - 8 - size_ip;                                   // the size of the data 
		insert(s_port,d_port,s_ip,d_ip, size_data,"udp");				
	}
	// the data I have been collected until now is: src and dst ports ,
	// level 4 protocal , src and dst ip 
}




/**
* converting IP fron uint yo char[16]
* param uint ip : the ip to convert
* param char* buffer: pointer to the IP buffer 
* return : the arr of the IP
*/
void convert_ip(unsigned int ip, char* buffer)
{                               
	int first, second, third, fourth;
	fourth = ip % 256;
	ip /= 256;
	third = ip % 256;
	ip /= 256;
	second = ip % 256;
	ip /= 256;
	first = ip % 256;
	sprintf(buffer, "%d.%d.%d.%d", fourth, third, second, first);
	
}




