#ifndef SNIFFER_H_INCLUDED
#define SNIFFER_H_INCLUDED
#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <pfring.h>
#include <malloc.h>
#include <string.h>
#include "headers.h"


/**
 * the Connection Struct
 */
 
typedef struct list_log
{
	int used;																	// if the log is used, or it's free 
	char src_ip[16];															// the src IP 
	char dst_ip[160];															// the dst IP
	int src_port;																// the src_port 
	int dst_port;																// the dst_port
	char porto[5];																// the protocol 
	int packet_counter;															// counter of the packets 
	int total_data;																// total data of the packet 
	int time;																	// the time now, using for timeout 
	int next;																	// default is -1, inserting the index of the next log with the same hash 
} log;


/**
 * terminal signal handler 
 */
void signal_handler(int signum);

/**  creating new index 
*  @param index: the index of the new log 
* @param s_port: source port
* @param d_port: dst port
* @param s_ip: src IP
* @param d_ip: dst IP
* @param size: size of the packet data
* @param porto: the protocol
*/
void newlog(int index,int s_port,int d_port, char* s_ip,char* d_ip
							,int size,char* porto);

/* Prototypes for the functions */

/*  getting index by hash
* @param s_port: source port
* @param d_port: dst port
* @param s_ip: src IP
* @param d_ip: dst IP
* @param size: size of the packet data
* @param porto: the protocol
*/
int getIndex(int s_port,int d_port, char* s_ip,char* d_ip
							,int size,char* porto);
							
/**
 * if there is a log file, writing the string to the file 
 */
void writeLog(char* str);

/**
 * not my method , creating a hash of string
 */
int str2md5(unsigned char *str);


/**
* method that enters the data to the array of logs
* @param s_port: source port
* @param d_port: dst port
* @param s_ip: src IP
* @param d_ip: dst IP
* @param size: size of the packet data
* @param porto: the protocol
*/
char* insert(int s_port, int d_port, char* s_ip, char* d_ip, int size, char* porto);

/**
 * getting command line arguments with the "getopt" method
 * @param argc: arguments counter 
 * @param argv: the array of arguments 
 * ******* return ?
 */
int getargs(int argc, char *argv[]);


/**
* starting the sniffer
* param def: the device to sniff e.g. 'eth0'
* param filter: the filter of sniffing e.g. 'tcp and udp'
*/
void start_binding(char dev[], char* filter);

/**
* Writing the log to the file and freeing the space in the log
*/
void flush();

/**
* converting little endian to big endian and big endian to little
* param unsigned short a: pointer to the address to swap endian
*/
void endian(unsigned short *a);

/**
* the packet hendler
* param *hdr: the header of the packet
* param *pkt: the whole packet data
*/
void packet_handler(const struct pfring_pkthdr *hdr, unsigned char*pkt);

/**
* converting IP fron uint yo char[16]
* param uint ip : the ip to convert
* param char* buffer: pointer to the IP buffer 
* return : the arr of the IP
*/
void convert_ip(unsigned int ip, char* buffer);

/**
 * comparing function to use in qsort
 * true if the time of the first packet is before the second 
 */
int cmpfunc(const void * a, const void * b);

#endif
