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

#define USE_MESA_SOCKET_WRAP		(1)

#define RAND_SLEEP_ENABLE			(0)

#define CLIENT_NUM	(1)
#define BUF_LEN		(2048)
#define READ_BUF_LEN	(100)
#define SEND_BUF_LEN	(2048)
#define SERV_PORT		(9999)

static volatile long tot_read_len = 0;
static volatile long tot_send_len = 0;

#if USE_MESA_SOCKET_WRAP
int g_timeout = 10;
#else
int g_timeout = 0;
#endif

void inline test_sleep(void)
{
#if RAND_SLEEP_ENABLE
	usleep(rand() % 10 + 1);
#endif
}

void *muti_test_stat_thread(void *arg)
{
	while(1){
		printf("tot_read_len: %ld, \n", tot_read_len);
		tot_read_len = 0;
		printf("tot_send_len: %ld, \n\n", tot_send_len);
		tot_send_len = 0;
		sleep(1);
	}

	return NULL;
}

void *client_thread(void *arg)
{
	char buf[BUF_LEN];
	int ret, sockfd;
	struct sockaddr_in s_addr;

	sleep(3);

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	
	memset(&s_addr, 0, sizeof(s_addr));
	s_addr.sin_family = AF_INET;
	s_addr.sin_port = htons(SERV_PORT);
	inet_pton(AF_INET, "127.0.0.1", &s_addr.sin_addr.s_addr);

	ret = MESA_sock_connect(sockfd, (const struct sockaddr *)&s_addr, sizeof(struct sockaddr_in), g_timeout);
	if(ret != 0){
		printf("connect error, %s!\n", strerror(errno));
		return NULL;
	}else{
		printf("connect OK, fd= %d!\n", sockfd);
	}

	while(1){
		ret = MESA_sock_force_write(sockfd, buf, SEND_BUF_LEN, 0);
		//if((ret < 0) && (ret != MESA_SOCK_TIMEOUT)){
		if(0){
			printf("sockfd %d error:%d\n", sockfd, ret);
			return NULL;
		}
		ret = MESA_sock_greedy_read(sockfd, buf, READ_BUF_LEN, 0);	
		//if((ret < 0) && (ret != MESA_SOCK_TIMEOUT)){
		if(0){
			printf("sockfd %d error:%d\n", sockfd, ret);
			return NULL;
		}
		//test_sleep();
	}

	return NULL;
}

void *rcv_thread(void *arg)
{
	char buf[BUF_LEN];
	int rd_ret = 0, wr_ret = 0;
	int sockfd = *((int *)arg);

	printf("create new recver, %d!\n", sockfd);

	int flags = 0;
	flags = fcntl(sockfd, F_GETFL, 0);
	fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
	
	while(1)
	{
		rd_ret = read(sockfd, buf, READ_BUF_LEN);
		if((rd_ret < 0) &&(errno != EAGAIN)){
			printf("sockfd %d error:%d\n", sockfd, wr_ret);
			return NULL;
		}
		if(rd_ret > 0){
			tot_read_len += rd_ret;
		}
		
		//wr_ret = write(sockfd, buf, SEND_BUF_LEN);
		wr_ret = MESA_sock_writen(sockfd, buf, SEND_BUF_LEN);
		if((rd_ret < 0) &&(errno != EAGAIN)){
			printf("sockfd %d error:%d\n", sockfd, wr_ret);
			return NULL;
		}
		if(wr_ret > 0){
			tot_send_len += wr_ret;
		}

		//test_sleep();
		usleep(2);
	}
	
	return NULL;
}


int main(void)
{
	struct sockaddr_in servaddr, cliaddr;
	socklen_t cliaddr_len;
	//char str[INET_ADDRSTRLEN];
	int i, listenfd, connfd, on = 1;
	pthread_t rcv_pid, stat_pid, client_pid;

	pthread_create(&stat_pid, NULL, muti_test_stat_thread, NULL);

	for(i = 0; i < CLIENT_NUM; i++){
		pthread_create(&client_pid, NULL, client_thread, NULL);
	}

	listenfd = socket(AF_INET, SOCK_STREAM, 0);

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(SERV_PORT);

	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int));

	if(bind(listenfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0){
		printf("bind error!\n");
	}
	//bind fd and "address:port" together

	listen(listenfd, 20); //getready for order services

	printf("Accepting connections ...\n");
	while (1) {
		cliaddr_len = sizeof(cliaddr);
		connfd = accept(listenfd, (struct sockaddr *) &cliaddr, &cliaddr_len);

		pthread_create(&rcv_pid, NULL, rcv_thread, &connfd);
	
		sleep(1);
	}

	return 0;
}
