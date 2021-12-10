#include "sniffer.h"
#include <time.h>
#define SIZE 10


/*
   Extern variables 
 */
extern int* indexes;																	// list of all the indexes 
extern char fileName[100];
extern int* freeindex;																	// list of free indexes 
extern log* logs;																		// the log list 
extern int _size;																		// the size of my array of connections 


/* Method */

void main(int argc, char *argv[])
{
	strcpy(fileName,"output");
	_size = SIZE;
	printf("UnitTest\n");
	log* temp = calloc(sizeof(log), SIZE);		
	logs = temp;														          // main buffer 
	int* temp1 = calloc(sizeof(int), SIZE);
	freeindex = temp1;												           	// freeindexes buffer
	int* temp2 = calloc(sizeof(int), SIZE);	
	indexes = temp2;
	check_free();
	check_insert();
}


/**
 * function that checks the "free" function in sniffer.c
 */
int check_free()
{

int i;
    /* inserting data to the arrays */
    for(i=SIZE-1;i>=0;i--)
    {
        logs[i].used = 1;
        logs[i].time = time(NULL);
		logs[i].next = -1;
    }
    for(i=0;i<SIZE;i++)
    {
        freeindex[i]=-1;
        indexes[i] = i;
    }
    for (i=0;i<SIZE;i++)
    {
        printf("%d ", indexes[i]);
    }
    /* calling the function*/ 
    flush();
    /* checking output */
    for(i=SIZE-1;i>=0;i--)
    {
        /* checking indexes array */
        if(indexes[i]=i)
        {
            printf("indexes: %d -> ok\n", i);
        }
    }
    for (i=0;i<SIZE/2;i++)
    {
        /* checking logs array */
        if(logs[indexes[i]].used == 0)
        {
            printf(" %d -> ok \n",i);
        }
        else
        {
            printf(" %d -> error \n",i);
        }
    }
    for(i=0;i<SIZE/2;i++)
    {
        /* checking freeindexes array */
        if(freeindex[indexes[i]]==indexes[i])
        {
            printf(" freeindex: %d -> ok\n",indexes[i]);
        }
        else
        {
            printf(" freeindex: %d -> error\n",indexes[i]);    
        }
    }

    return 1;
}


/** checking insert fucntion */
int check_insert()
{
int i;
    insert(213,123,"123","213",123,"123");
    for(i=0;i<SIZE;i++)
    {
        if(logs[i].used)
        {
            if(!strcmp(logs[i].src_ip,"123") &&!strcmp( logs[i].dst_ip,"213"))
            {
                printf("ok\n");
                return 1;
            }
        }
    }
    return 0;
    
}

