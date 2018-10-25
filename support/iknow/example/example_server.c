#include "iknow.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C"
{
#endif

static iknow_handle ik_handle = NULL;

static long show_tcp_stream_cb(iknow_handle ihandle, iknow_conn iconn, const void *cmd_cb_arg, const char *cmd_args)
{
	iprintf(ihandle, iconn, "tcp streaminfo:\nnew   :\t12345/s\ndel:   \t234/s\ntotal:\t98765\n");
}

static long show_udp_stat_cb(iknow_handle ihandle, iknow_conn iconn, const void *cmd_cb_arg,const char *cmd_args)
{
	iprintf(ihandle, iconn, "udp stat:\nbps:123434b/s\npps:23455/s\n");
}

static long show_ip_stat_cb(iknow_handle ihandle, iknow_conn iconn, const void *cmd_cb_arg,const char *cmd_args)
{
	iprintf(ihandle, iconn, "ip stat:\nbps:673434b/s\npps:93455/s\n");
}

static long show_http_bps_cb(iknow_handle ihandle, iknow_conn iconn, const void *cmd_cb_arg,const char *cmd_args)
{
	printf("I#show http bps\n");
	iprintf(ihandle, iconn, "http bps: 100Kb/s\n");
}

static long show_http_pps_cb(iknow_handle ihandle, iknow_conn iconn, const void *cmd_cb_arg,const char *cmd_args)
{
	printf("I#show http pps\n");
	iprintf(ihandle, iconn, "http pps: 20000n/s\n");
}

static long show_ftp_pps_cb(iknow_handle ihandle,iknow_conn iconn, const void *cmd_cb_arg,const char *cmd_args)
{
	printf("I#show ftp pps\n");
	iprintf(ihandle, iconn, "ftp pps: 300n/s\n");
}

static long show_ftp_bps_cb(iknow_handle ihandle, iknow_conn iconn, const void *cmd_cb_arg,const char *cmd_args)
{
	printf("I#show ftp bps\n");
	iprintf(ihandle, iconn, "ftp bps: 33Kb/s\n");
}

static void global_log_test(void)
{
	int i;

	for(i = 0; i < 5; i++){
		ibroadcast(ik_handle, i, "http", "global log example, module:http, level:%d\n", i);
	}

	for(i = 0; i < 5; i++){
		ibroadcast(ik_handle, i, "ftp", "global log example, module:ftp, level:%d\n", i);
	}

	for(i = 0; i < 5; i++){
		ibroadcast(ik_handle, i, "smtp", "global log example, module:smtp, level:%d\n", i);
	}

	for(i = 0; i < 5; i++){
		ibroadcast(ik_handle, i, "pop3", "global log example, module:pop3, level:%d\n", i);
	}

	for(i = 0; i < 5; i++){
		ibroadcast(ik_handle, i, "dns", "global log example, module:dns, level:%d\n", i);
	}

	return;
}

int main(void)
{
	iknow_create_args_t cargs;

	memset(&cargs, 0, sizeof(iknow_create_args_t));

	cargs.listen_port_host_order = 22;
	cargs.max_users = 100;
	
	ik_handle = iknow_create(&cargs, sizeof(iknow_create_args_t));
	iknow_register_cmd(ik_handle, "show http bps", "cmd intro", show_http_bps_cb, NULL, 0, "arg intro");

	iknow_register_cmd(ik_handle, "show http bps", "cmd intro", show_http_bps_cb, NULL, 0, "arg intro");
	iknow_register_cmd(ik_handle, "show http pps", "cmd intro", show_http_pps_cb, NULL, 0, "arg intro");
	iknow_register_cmd(ik_handle, "show ftp bps", "cmd intro", show_ftp_bps_cb, NULL, 0, "arg intro");
	iknow_register_cmd(ik_handle, "show ftp pps", "cmd intro", show_ftp_pps_cb, NULL, 0, "arg intro");
	iknow_register_cmd(ik_handle, "show ftp pps", "cmd intro", show_ftp_pps_cb, NULL, 0, "arg intro");
	iknow_register_cmd(ik_handle, "show http", "cmd intro", NULL, NULL, 0, "arg intro");

	iknow_register_cmd(ik_handle, "show tcp streaminfo", "cmd intro", show_tcp_stream_cb, NULL, 0, "arg intro");
	iknow_register_cmd(ik_handle, "show udp stats", "cmd intro", show_udp_stat_cb, NULL, 0, "arg intro");
	iknow_register_cmd(ik_handle, "show ip stats", "cmd intro", show_ip_stat_cb, NULL, 0, "arg intro");

	iknow_run(ik_handle);

	while(1){
		global_log_test();
		sleep(2);
	}

	return 0;
}

#ifdef __cplusplus
}
#endif


