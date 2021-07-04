#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#if 0 // for EAL check, Delete code temporary
#define	TEST_CNT	(8)
#define	TEST_THREAD	(4)
struct test_case_t
{
	void *mem;
	unsigned int size;
};
unsigned int g_used_mem_size=0;

void mem_test(void*)
{
	struct test_case_t test_array[TEST_CNT];
	int i=0;
	for(i=1;i<TEST_CNT;i++)
	{
		test_array[i].size=i*64;
		test_array[i].mem=malloc(test_array[i].size);
		g_used_mem_size+=test_array[i].size;
	}
	sleep(10);
	for(i=1;i<TEST_CNT;i++)
	{
		switch(i%10)
		{
			case	5:
				g_used_mem_size-=test_array[i].size;
				test_array[i].size+=1500;
				test_array[i].mem=realloc(test_array[i].mem,test_array[i].size);
				g_used_mem_size+=test_array[i].size;
				break;
			case	2:
				free(test_array[i].mem);
				g_used_mem_size-=test_array[i].size;
				test_array[i].size=0;
				test_array[i].mem=NULL;
				break;
			default:
				break;
		}
	}

	for(i=1;i<TEST_CNT;i++){
		free(test_array[i].mem);
	}
}
int main(int argc,char* argv[])
{
	pthread_t	 thread_desc[TEST_THREAD];
	pthread_attr_t attr;
	int i=0;
	memset(&thread_desc, 0, sizeof(thread_desc));
	memset(&attr, 0, sizeof(attr));	
	
	if(0 != pthread_attr_init(&(attr))) 
	{
		fprintf(stderr,"pthread_attr_init(): %d %s", errno, strerror(errno));
		return -1;
	}
	if(0 != pthread_attr_setdetachstate(&(attr), PTHREAD_CREATE_DETACHED)) 
	{
		fprintf(stderr,"pthread_attr_setdetachstate(): %d %s", errno, strerror(errno));
		return -1 ;
	}
	for(i=0;i<TEST_THREAD;i++)
	{
		if(0 != pthread_create(&(thread_desc[i]), &(attr), (void *(*)(void *))(mem_test), NULL))
		{
			fprintf(stderr,"pthread_create(): %d %s", errno, strerror(errno));
			pthread_attr_destroy(&(attr));
			return -1;
		}
	}
	sleep(5);
	return 0;
}
#else
int main(int argc,char* argv[])
{
	return 0;
}

#endif

