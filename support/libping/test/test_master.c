#ifdef __cplusplus
extern "C" {
#endif
#include "libping.h"
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

void show_slave_status(ping_handle ph)
{
	int i, ret;
	int node_array[100];
	int node_num;
	node_status_t node_stat;
	int len;
	char ip_str[16];

	node_num = 100;
	ret = libping_get_opt(ph, PO_NODE_LIST, node_array, &node_num);
	if(ret >= 0){
		printf("slave node num: %d\n", node_num);
		printf("\t%3s %10s %16s %11s %12s %10s %10s\n", "seq", "slave-id", "slave-ip", "slave-port", "slave-state", "snd", "rcv");
		for(i = 0; i < node_num; i++){
			len = sizeof(int);
			node_stat.slave_id = node_array[i];
			libping_get_opt(ph, PO_NODE_STATUS, &node_stat, &len);
			inet_ntop(AF_INET, &node_stat.slave_ip_net, ip_str, 16);
			printf("\t%3d %10d %16s %11u %12d %10u %10u\n", 
			        i, node_array[i], ip_str, ntohs(node_stat.slave_port_net), node_stat.state,
			        node_stat.send_req_pkt, node_stat.recv_rep_pkt);
		}
	}

	return;
}

int main(void)
{
	int opt_int;
	short opt_short;
	
	ping_handle ph = libping_create();

	opt_int = 12345;
	libping_set_opt(ph, PO_PAIR_TAG, &opt_int, sizeof(int));
	
	opt_short = LIBPING_WORK_MODE_MASTER;
	libping_set_opt(ph, PO_WORK_MODE, &opt_short, sizeof(short));

	libping_run(ph);

	while(1){
		show_slave_status(ph);
		sleep(1);
	}
	
	return 0;
}


#ifdef __cplusplus
}
#endif
