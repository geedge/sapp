#ifndef __USE_BSD
#define __USE_BSD
#endif
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/types.h>			/* See NOTES */
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/limits.h>
#include <linux/if_ether.h>
#include <pthread.h>
#include "stream.h"
#include "gtest_sapp_fun.h"


extern "C" char perf_test_entry(struct streaminfo *pstream, void **pme, int thread_seq,void *a_packet)
{
	int *test_pme = NULL;
	
	if(OP_STATE_PENDING == pstream->opstate){
		/* 模拟最简单的插件, malloc, free操作 */
		test_pme = (int *)malloc((rand() % 1234) + 100);
		assert(test_pme);
		*pme = test_pme;
		printf("stream:%p pending, save pme:%p.\n", pstream, test_pme);
	}
	
	if(OP_STATE_CLOSE == pstream->opstate){
		free(*pme);
	}
	
	return APP_STATE_GIVEME;
}


