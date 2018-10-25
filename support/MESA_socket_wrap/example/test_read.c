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

#define SERV_PORT		(9999)
#define BUF_LEN		(2048)

int main(void)
{
	struct sockaddr_in servaddr, cliaddr;
	socklen_t cliaddr_len;
	//char str[INET_ADDRSTRLEN];
	int listenfd, connfd, ret, on = 1;
	char buf[BUF_LEN];

	listenfd = socket(AF_INET, SOCK_STREAM, 0);

	bzero(&servaddr, sizeof(servaddr));
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

		printf("a new client:%d!\n", connfd);
		while(1){

#if 0		
			ret = MESA_sock_can_be_read(connfd, 2000);
			if(1 == ret){
				printf("can be read!\n");
			}else{
				printf("can't be read!!!\n");
			}
#endif

#if 0
			ret = MESA_sock_can_be_write(connfd, 1500);
			if(1 == ret){
				printf("can be write!\n");
			}else{
				printf("can't be write:%d!!\n", ret);
				ret = write(connfd, "why?!\n", 6);
				if(ret > 0){
					printf("####but write %d bytes indeed!\n", ret);
				}
			}
			continue;
#endif
		
			ret = MESA_sock_greedy_read(connfd, buf, 5, 5000);
			if(0 == ret){
				printf("peer closed!\n");
				close(connfd);
				break;
			}else if(ret < 0){
				
				if(ret == MESA_SOCK_TIMEOUT){
					printf("read timeout.\n");
				}else{
					break;
				}
			}else{
				printf("\n --read data:%dB --:\n", ret);
				write(1, buf, ret);
			}
		}
	}

	return 0;
}

