#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/limits.h>
#include <pcap/pcap.h>
#include "stream.h"
#include <pthread.h>

extern "C" int libsapp_setup_env(int argc, char *argv[]);
extern "C" void libsapp_destroy_env(void);

static volatile int sapp_state;
static 	int i;
static int sleep_interval = 5;
static void *test_sapp_destroy(void *arg)
{
	while(1){
		sleep(sleep_interval);

		if(1 == sapp_state){
			libsapp_destroy_env();
			printf("$$$$$$$$$$$$ %, libsapp_destroy_env() success!\n", i);
			sapp_state = 0;
		}
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	pthread_t pid;

	pthread_create(&pid, NULL, test_sapp_destroy, NULL);

	while(1){
		printf("argc:%d, argv[] = %s\n", argc, argv[0]);

		sapp_state = 0;
		if(libsapp_setup_env(argc,argv) < 0){
			printf("%d, ############### libsapp_setup_env() error!\n", i);
			exit(1);
		}else{
			printf("%d, !!!!!!!!!!!!!!  libsapp_setup_env() success!\n", i);
		}

		sleep(sleep_interval);

		sapp_state = 1;
		
		while(1 == sapp_state){
			usleep(1000);
		}
		i++;
	}

	return 0;	
}

