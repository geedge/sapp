#include "MESA_socket_wrap.h"
#include <sys/types.h> 
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>
#include <arpa/inet.h>

#define SEND_BUF_LEN							(1460)
#define USE_NON_BLOCK_TYPE					(0)
#define STATS_STR_LEN	(64)

static volatile unsigned long tot_send = 0;
static char send_data[SEND_BUF_LEN];

static unsigned long TO_KB = 1024;
static unsigned long TO_MB = 1024 * 1024;
static unsigned long TO_GB = 1024 * 1024 * 1024UL;
static unsigned long TO_TB;

static char *byte_convert_human(unsigned long bytes, int interval, char *byte_str, int multiple, char *unit)
{
    bytes *= multiple; /* to network pattern, or human pattern */
    bytes /= interval; /* per second */

    if(bytes < TO_KB){
        snprintf(byte_str,STATS_STR_LEN,"%lu%s", bytes, unit);
    }else if(bytes < TO_MB){
        snprintf(byte_str,STATS_STR_LEN,"%.2fK%s", (float)bytes/TO_KB, unit);
    }else if(bytes < TO_GB){
        snprintf(byte_str,STATS_STR_LEN,"%.2fM%s", (float)bytes/TO_MB, unit);
    }else if(bytes < TO_TB){
        snprintf(byte_str,STATS_STR_LEN,"%.2fG%s", (float)bytes/TO_GB, unit);
    }else{
        snprintf(byte_str,STATS_STR_LEN,"%.2f T%s", (double)bytes/TO_TB, unit);	
    }

    return byte_str;
}

void *stat_thread(void *arg)
{
	char speed[STATS_STR_LEN];

	TO_TB = (unsigned long)1024 * 1024 * 1024 * 1024;
	
	while(1){
		printf("speed: %s\n", byte_convert_human(tot_send, 2, speed, 8, "bps"));
		tot_send = 0;
		sleep(2);
	}

	return NULL;
}

static void test_mesa_sock_strerror(void)
{
	int i;
	
	for(i = 0; i >=  __MESA_SOCK_ERRNO_MAX; i--){
		printf("%d    %s\n", i, MESA_sock_strerror(i));
	}
}

int main(void)
{
	char *dip = "10.0.6.201";
	unsigned short dport = 9999;
	struct sockaddr_in s_addr;
	int i, conn_fd, ret;
	pthread_t pid;

	test_mesa_sock_strerror();

	srand(time(NULL));

	signal(SIGPIPE, SIG_IGN);

	for(i = 0; i < SEND_BUF_LEN; i++){
	    send_data[i] = rand()%26 + 0x61;
	}

	pthread_create(&pid, NULL, stat_thread, NULL);
	    
	memset(&s_addr, 0, sizeof(s_addr));
	s_addr.sin_family = AF_INET;
	s_addr.sin_port = htons(dport);
	inet_pton(AF_INET, dip, &s_addr.sin_addr.s_addr);

	conn_fd = socket(AF_INET, SOCK_STREAM, 0);

#if USE_NON_BLOCK_TYPE
	int flags = 0;
	flags = fcntl(conn_fd, F_GETFL, 0);
	fcntl(conn_fd, F_SETFL, flags | O_NONBLOCK);
#endif

	ret = MESA_sock_connect(conn_fd, (const struct sockaddr *)&s_addr, sizeof(struct sockaddr_in), 5000);
	if(ret < 0){
		printf("connetc to %s:%u error:%d!\n", dip, dport, ret);
		return -1;
	}else{
		printf("connetc to %s:%u OK!\n", dip, dport);
	}

	while(1){
		ret = MESA_sock_force_write(conn_fd, send_data, SEND_BUF_LEN, 1000);
		if(ret < 0){
			printf("errno = %d, exit!!\n", ret);
			if(ret != MESA_SOCK_TIMEOUT){
				break;
			}
		}

		tot_send += ret;
	}

	return 0;
}

