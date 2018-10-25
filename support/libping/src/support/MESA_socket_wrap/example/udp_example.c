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

static unsigned short bind_port = 9999;
static unsigned short remote_port = 9999;

int main(void)
{
	int sockfd, ret;
	struct sockaddr_in remote_addr, bind_addr;
	//socklen_t addr_len;
	//char rcv_buf[2048];
	int on = 1;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	bzero(&bind_addr, sizeof(bind_addr));
	bind_addr.sin_family = AF_INET;
	bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	bind_addr.sin_port = htons(bind_port);

	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int));

	if(bind(sockfd, (struct sockaddr *) &bind_addr, sizeof(struct sockaddr_in)) < 0){
		printf("bind error!\n");
	}
	
	//socklen_t addr_len = sizeof(struct sockaddr_in);

	while(1){
#if 0
		ret = MESA_sock_recvfrom(sockfd, rcv_buf, 2048, 0, (struct sockaddr *)&remote_addr, &addr_len,  0);
		if(ret > 0){
			printf("recv from %x:%u %d bytes!\n", remote_addr.sin_addr.s_addr, remote_addr.sin_port, ret);
		}else{
			printf("recv error, %d!\n", ret);
		}
#else
		remote_addr.sin_family = AF_INET;
		inet_pton(AF_INET, "10.0.6.201", &remote_addr.sin_addr.s_addr);
		remote_addr.sin_port = htons(remote_port);

		ret = MESA_sock_can_be_write(sockfd, 1000);
		if(1 == ret){
			ret = MESA_sock_sendto(sockfd, "test send\n", 10, 0, (struct sockaddr *)&remote_addr, sizeof(struct sockaddr_in), 1000);
			printf("can be send\n");
		}else{
			printf("can't send, %d!\n", ret);
		}
#endif

	}
	
	return 0;
}

