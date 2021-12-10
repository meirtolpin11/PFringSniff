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
#include <signal.h>
#include <string.h>
#include "sniffer.h"

#define PORT_RANGE 65535                                                        // number of ports

/*** insert new functions to sniffer.h */
/**
 * Global Variables
 */
 
int indexp = 0;																	// index pointer
int freepointer = 0;															// pointer to the list of free indexes 
int* indexes;																	// list of all the indexes
int* freeindex;																	// list of flush indexes 
log* logs;																		// the log list 
int _size;																		// the size of my array of connections 
char logFile[1000];
int isLog = 0;
char fileName[100];
char to_bind[100];
/** methods **/

/**
 * terminal signal handler 
 */
void signal_handler(int signum)
{
	/* ctrl+c */
	if(signum == 2)
	{
		writeLog("***last flush***\n");
		/* log file name must be a command line parameter*/
		FILE* f = fopen(fileName, "a");											// opening file for writing 
		int i = 0;			
		for (i = 0; i < _size; i++)												// deleting the first half of the indexes 
		{
			if(!logs[indexes[i]].used)
			{
				continue;
			}
			logs[indexes[i]].used = 0;												// setting to unused 
			fprintf(f, "%s;%s;%d;%d;%d;%s\n"
				, logs[indexes[i]].src_ip, logs[indexes[i]].dst_ip,
				logs[indexes[i]].src_port, logs[indexes[i]].dst_port, 
				logs[indexes[i]].total_data , logs[indexes[i]].porto);  			// writing to file 
		}
		fclose(f);
		exit(2);
	}
	/* HUP */
	else if(signum == 1)
	{
		printf("\nhup\n");
		char temp[100];
		strcpy(temp,fileName);
		strcat(temp,"_old");
		writeLog("Renaming file\n");
		if(!rename(fileName,temp))
		{
			writeLog("succeed renaming file\n");	
			FILE* f = fopen(fileName,"w");												// cleaning the file 
			fprintf(f,"src_ip;dst_ip;src_port;dst_port;size;packets;porto\n");
			fclose(f);
		}
		else
		{
			writeLog("error renaming file\n");  
		}
	}
	
	
}

/**
 * comparing function to use in qsort
 * true if the time of the first packet is before the second 
 */
int cmpfunc(const void * a, const void * b)
{
	/*** check n*/
	if(logs[*(int*)a].time > logs[*(int*)b].time)
	{
		return 1;
	}
	else if(logs[*(int*)a].time < logs[*(int*)b].time)
	{
		return -1;
	}
	return 0;
}


/**
* Writing the log to the file and freeing the space in the log
*/
void flush()
{
	writeLog("*****Writing to file*****\n");
	FILE* f = fopen(fileName, "a");   											// opening file for writing 
	int i = 0;
	qsort(indexes, _size, sizeof(int), cmpfunc);								// sorting the list of indexes by time
	freepointer = 0;															// setting freepointer to 0 
	for (i = 0; i < _size / 2; i++)												// deleting the first half of the indexes 
	{
		logs[indexes[i]].used = 0;												// setting to unused 
		/*csv*/
		fprintf(f, "%s;%s;%d;%d;%d;%d;%s\n"
			, logs[indexes[i]].src_ip, logs[indexes[i]].dst_ip,
			logs[indexes[i]].src_port, logs[indexes[i]].dst_port, 
			logs[indexes[i]].total_data ,logs[indexes[i]].packet_counter,logs[indexes[i]].porto);  			// writing to file 
		
		freeindex[indexes[i]] = indexes[i];										// inserting new flush index 
		indexes[i] = 0;
	}
	indexp = 0;
	fclose(f);

}



void writeLog(char* str)
{
	if(isLog)
	{
		FILE* f = fopen(logFile, "a");	
		fprintf(f, str);
		fclose(f);
	}
}

/**
 * getting command line arguments with the "getopt" method
 * @param argc: arguments counter 
 * @param argv: the array of arguments 
 */
int getargs(int argc, char *argv[])
{
	/***** check *****/
	int allocated = 0;
	int size;
	int opt;
	int filename = 0;															// boolean 
	while ((opt = getopt(argc, argv, "s:o:l:b:h")) != -1) {
        switch (opt) {
        	case 's':
			size = atoi(optarg);
        		_size = size;
			writeLog(" Creating buffer \n");
			log* temp = calloc(sizeof(log),_size);
			logs = temp;														// main buffer 
			int* temp1 = calloc(sizeof(int),_size);
			freeindex = temp1;													// freeindexes buffer
			int* temp2 = calloc(sizeof(int),_size);
			indexes = temp2;
			writeLog("alocated \n");
			allocated = 1;
			break;
		case 'b':
			strcpy(to_bind,optarg);
			break;
		case 'l':
			isLog =1 ;
			strcpy(logFile,optarg);
			FILE *f = fopen(optarg,"w");
			fclose(f);
			break;
		case 'h':
			printf("-s [size] \n -o -> file to write \n -l -> optional log file \n -b -> the device to bind, default is wlan0 \n -h -> this menu \n");
			return(0);
			break;
		case 'o':
			strcpy(fileName,optarg);
			filename = 1;
			break;
        default: 
			printf("-s [size] \n -o -> file to write \n -l -> optional log file \n -b -> the device to bind, default is wlan0 \n -h -> this menu \n");
			return 0;
        }
    }
    if(allocated && filename)
    {
    	return 1;
    }
    printf("wrong arguments\n");
    return 0;
}


/** the main method of the program , recieves the size of the array as
 *  command line arguments , calls the getargs functions that creates the array 
 *  then starts the sniffer, every recieved packet sent to "packet handler" method
 * 	@param args: the count of the command line arguments, default in 1
 *  @param argv: command line arguments array
 */
void run(int argc, char *argv[])
{
	strcpy(to_bind,"wlan0");
	if(getargs(argc,argv)==0 )                                                  // getting options 
	{
		exit(0);
	}
	signal(SIGINT,signal_handler);
	signal(SIGHUP,signal_handler);
	
	int i;
	FILE* f = fopen(fileName,"w");												// cleaning the file 
	fprintf(f,"src_ip;dst_ip;src_port;dst_port;size;packets;porto\n");
	fclose(f);																	// closing the file 
	for(i=0;i<_size;i++)														// inserting the list of the indexes 
	{
		freeindex[i] = i;	
	}
	writeLog("starting the binder");
	start_binding(to_bind,"tcp or udp");										// starting the sniffer 
}


/**
 * not my method , creating a hash of string as int 
 */
int str2md5(unsigned char *str)
{
	unsigned long hash = 5381;
	int c;

	while (c = *str++)
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

	return hash;
}



/*  getting index by hash
* @param s_port: source port
* @param d_port: dst port
* @param s_ip: src IP
* @param d_ip: dst IP
* @param size: size of the packet data
* @param porto: the protocol
* return : hash index 
*/
int getIndex(int s_port,int d_port, char* s_ip,char* d_ip
							,int size,char* porto)
{
	char ss_port[7], dd_port[7], total[100];									// temp variables , used to create hash 
	snprintf(ss_port, 7,"%d",s_port);
	snprintf(dd_port, 7,"%d",d_port);
	strcpy(total, s_ip);														// creating the string, then creating a hash 
	strcat(total, d_ip);
	strcat(total, ss_port);
	strcat(total, dd_port);
	
	int data = str2md5(total);													// receiving the hash 
	int index = data % _size;
	return  index;
}

/*  creating new index 
*  @param index: the index of the new log 
* @param s_port: source port
* @param d_port: dst port
* @param s_ip: src IP
* @param d_ip: dst IP
* @param size: size of the packet data
* @param porto: the protocol
*/
void newlog(int index,int s_port,int d_port, char* s_ip,char* d_ip
							,int size,char* porto)
{
		indexes[indexp] = index;												// updating the list of indexes 
		indexp++;																// incrementing the pointer 
		strcpy(logs[index].src_ip, s_ip);										// inserting data 
		strcpy(logs[index].dst_ip, d_ip);
		logs[index].src_port = s_port;
		logs[index].dst_port = d_port;
		logs[index].packet_counter = 1;
		strcpy(logs[index].porto, porto);
		logs[index].total_data = size;
		logs[index].time = time(NULL);
		logs[index].next = -1;													// setting -1 as the next position 
		logs[index].used = 1;													// setting the log to "used" mod 
		freeindex[index] = -1;													// updating freeindexes array
}

/**
* method that enters the data to the array of logs
* @param s_port: source port
* @param d_port: dst port
* @param s_ip: src IP
* @param d_ip: dst IP
* @param size: size of the packet data
* @param porto: the protocol
* return : None 
*/
char* insert(int s_port, int d_port, char* s_ip, char* d_ip, int size, char* porto)
{
	int index = getIndex(s_port,d_port,s_ip,d_ip,size,porto);
	if(index<0)
	{
		index = 0;
	}																			// getting the position 
	int prevIndex = index;														// saving the index 
	/* checking if the position is empty, if so - entering properties */
	if (!logs[index].used)
	{
		newlog(index,s_port,d_port,s_ip,d_ip,size,porto);
	}
	/* if the position is used, finding next flush position */
	else
	{
		/*** changed the order of checking  now if index == -1 it stops immidiatly ***/
		while (index >=0 && (strcmp(logs[index].src_ip, s_ip) || strcmp(logs[index].dst_ip, d_ip) ||
			logs[index].dst_port != d_port || logs[index].src_port != s_port ||
			strcmp(logs[index].porto, porto)))									// checking if the log is the same , or its the last log with the same hash
		{
			prevIndex = index;													// setting prev index 
			index = logs[index].next;											// getting next index
		}
		/* finded log with the same data */
		if (index != -1)
		{
			logs[index].packet_counter++;
			logs[index].total_data += size;
			logs[index].time = time(NULL);
		}
		/* new log */
		else
		{
			while (index == -1)
			{
				/* getting the next free index */
				if (freepointer == _size)
				{
					// if the end of the array, that means that there is no more 
					// free indexes, so calling flush function , now the
					// freepointer is 0 
					writeLog("\n\n   freeing      \n\n");
					flush();
				}
				do
				{
					index = freeindex[freepointer];								// getting the next freeindex
					//writeLog("\nindex: %d\n",index);					
					if (index >= 0)
					{
						freeindex[index] = -1;									// setting the index to used
					}
					freepointer++;												// next index
					if (freepointer == _size&&index==-1)						// if end of the array clearing it
					{
						// if the end of the array, that means that there is no more 
						// free indexes, so calling flush function , now the
						// freepointer is 0 
						flush();
					}
					/* loop until recieving real index (not -1) */
				} while (index == -1);
			}
			/* creating new log */
			newlog(index,s_port,d_port,s_ip,d_ip,size,porto);													// next place in the array
			if (prevIndex == index||logs[prevIndex].used == 0){ index = -1; }
			logs[prevIndex].next = index;										// setting this index as the next of previous log
		}

	}
}

