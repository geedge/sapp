#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

static usage(const char *prog)
{
	printf("Usage: %s <ip address>\n", prog);
	exit(1);
}


int main(int argc, char *argv[])
{
	unsigned int raw_ip;
	unsigned int tun_ip;
	char new_ip_str[INET6_ADDRSTRLEN];
	
	if(argc != 2){
		usage(argv[0]);
	}

	if(inet_pton(AF_INET, argv[1], &raw_ip) <= 0){
		printf("ip address invalid!\n");
		return -1;
	}

	tun_ip = raw_ip ^ 0xFFFFFFFF;

	inet_ntop(AF_INET, &tun_ip, new_ip_str, sizeof(new_ip_str));

	printf("raw ip address is:%s\n", argv[1]);
	printf("tun ip address is:%s\n", new_ip_str);

	return 0;
}

