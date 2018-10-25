#ifdef __cplusplus
extern "C" {
#endif
#include "libping.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>

unsigned int g_slave_id = 12345;
       
static int libping_slave_pre_replay_cb_fun(ping_handle ph, unsigned int pair_tag, unsigned int slave_id)
{
	printf("recv request, but check app error, force not reply!\n");
	return 1;
}

static void show_plug_status(ping_handle ph)
{
	int i, ret;
	int node_stat_len;
	node_status_t node_stat;
	int len;

	memset(&node_stat, 0, sizeof(node_stat));
	node_stat_len = sizeof(node_stat);

	node_stat.slave_id = g_slave_id;

	ret = libping_get_opt(ph, PO_NODE_STATUS, &node_stat, &node_stat_len);
	if(ret >= 0){
		printf("plug state:%d\n", node_stat.state);
	}

	return;
}

int main(int argc, char *argv[])
{
	int opt_int;
	short opt_short;
	
	ping_handle ph = libping_create();

	opt_int = 12345;
	libping_set_opt(ph, PO_PAIR_TAG, &opt_int, sizeof(int));

	opt_short = LIBPING_WORK_MODE_SLAVE;
	libping_set_opt(ph, PO_WORK_MODE, &opt_short, sizeof(short));
	
	opt_int = (int)getpid();
	g_slave_id = opt_int;
	libping_set_opt(ph, PO_SLAVE_ID, &opt_int, sizeof(int));

	inet_pton(AF_INET, "127.0.0.1", &opt_int);
	libping_set_opt(ph, PO_MASTER_IP_NET_ORDER, &opt_int, sizeof(int));

	opt_short = htons(65000);
	libping_set_opt(ph, PO_MASTER_PORT_NET_ORDER, &opt_short, sizeof(short));
	
	//libping_set_opt(ph, PO_SLAVE_PRE_REPLAY_CB, &libping_slave_pre_replay_cb_fun, sizeof(void *));

	libping_run(ph);

	while(1){
		show_plug_status(ph);
		sleep(1);
	}
	
	return 0;
}


#ifdef __cplusplus
}
#endif

