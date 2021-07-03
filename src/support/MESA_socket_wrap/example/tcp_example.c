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

#define SOCK_BUF_LEN		(65536)
static unsigned short LOCAL_COMM_PORT = 11999;


static void test_communication(int connfd, const char *whoami)
{
	int ret, rand_len, rand_time;
	char buf[SOCK_BUF_LEN];

	while(1){
		rand_len = rand() % SOCK_BUF_LEN + 1;
		rand_time = rand() % 1000 + 100;
	
		ret = MESA_sock_greedy_read(connfd, buf, rand_len, rand_time);
		if(0 == ret){
			printf("%s: peer closed!\n", whoami);
			return;
		}else if(ret < 0){
			printf("%s: ~_~ read error:%d!\n", whoami, ret);
		}else{
			if(ret == rand_len){
				printf("%s: ^_^, read %dB OK!\n", whoami, ret);
			}else{
				printf("%s: ~_~, expect:%d, but only read %dB in %d ms!\n", whoami, rand_len, ret, rand_time);
			}
		}

		usleep(rand() % 500000 + 500000);

		rand_len = rand() % SOCK_BUF_LEN + 1;
		rand_time = rand() % 1000 + 100;
		
		ret = MESA_sock_force_write(connfd, buf, rand_len, rand_time);
		if(0 == ret){
			printf("%s: ~_~ buf full, do nothing!\n", whoami);
		}else if(ret < 0){
			if(MESA_SOCK_PEER_CLOSE == ret){
				printf("%s: peer closed!\n", whoami);
				return;
			}else{
				printf("%s: ~_~ want write %dB error:%d, in %dms!\n", whoami, rand_len, ret, rand_time);
			}
		}else{
			if(ret == rand_len){
				printf("%s: ^_^, write %dB OK!\n", whoami, ret);
			}else{
				printf("%s: ~_~, expect:%d, but only write %dB in %d ms!\n", whoami, rand_len, ret, rand_time);
			}
		}

		usleep(rand() % 500000 + 500000);
	}

	return;
}

void *client_thread(void *arg)
{
	//char buf[SOCK_BUF_LEN];
	int ret, connfd;
	struct sockaddr_in conn_addr;

	connfd = socket(AF_INET, SOCK_STREAM, 0);
	
	memset(&conn_addr, 0, sizeof(conn_addr));
	conn_addr.sin_family = AF_INET;
	conn_addr.sin_port = htons(LOCAL_COMM_PORT);
	inet_pton(AF_INET, "10.0.6.205", &conn_addr.sin_addr.s_addr);

	ret = MESA_sock_connect(connfd, (const struct sockaddr *)&conn_addr, sizeof(struct sockaddr_in), 2000);
	if(ret < 0){
		printf("client: connect error:%d!\n", ret);
		exit(1);
	}

	test_communication(connfd, "client");

	return NULL;
}

void *server_thread(void *arg)
{
	int listenfd, connfd;
	struct sockaddr_in listen_addr, cliaddr;
	int opt_value;
	socklen_t cliaddr_len;
	
	listenfd = socket(AF_INET, SOCK_STREAM, 0);

	memset(&listen_addr, 0, sizeof(listen_addr));
	listen_addr.sin_family = AF_INET;
	listen_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	listen_addr.sin_port = htons(LOCAL_COMM_PORT);

	opt_value = 1;
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt_value, sizeof(int));

	if(bind(listenfd, (struct sockaddr *) &listen_addr, sizeof(listen_addr)) < 0){
		printf("bind port %u error!\n", LOCAL_COMM_PORT);
		exit(1);
	}

	listen(listenfd, 10); //getready for order services

	printf("Accepting connections ...\n");
	while (1) {
		cliaddr_len = sizeof(cliaddr);
		connfd = accept(listenfd, (struct sockaddr *) &cliaddr, &cliaddr_len);
		if(connfd > 0){
			test_communication(connfd, "\t\t\t\t\tserver");
		}
		sleep(1);
	}

	return NULL;
}

int main(void)
{
	pthread_t cpid,spid;

	srand(time(NULL));

	pthread_create(&spid, NULL, server_thread, NULL);
	sleep(1);
	pthread_create(&cpid, NULL, client_thread, NULL);

	while(1){
		sleep(3);
		srand(time(NULL));
	}
	
	return 0;
}


