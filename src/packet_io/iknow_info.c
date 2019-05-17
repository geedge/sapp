#ifdef __cplusplus
extern "C" {
#endif

#if DEBUG
#include "iknow.h"
#include "sapp_api.h"
#include "sapp_private_api.h"

iknow_handle PLATFORM_IHANDLE;

extern volatile unsigned long long g_SysInputInfo[MAX_THREAD_NUM][COUNTER_NUM];
extern int g_packet_io_thread_num;


static int iknow_cmd_init(void)
{
	return 0;
}

int iknow_info_init(void)
{
	unsigned int tport;
	iknow_create_args_t iargs;
	
	MESA_load_profile_uint_def((char *)"conf/main.conf", (char *)"ShowStatInfo",(char *) "iknow_listen_port", &tport, 65432);
	if(tport <= 0 || tport > 65535){
		printf("Invalid cfg 'iknow_listen_port', port=%u\n", tport);
		return -1;
	}

	memset(&iargs, 0, sizeof(iknow_create_args_t));
	iargs.listen_port_host_order = (unsigned short)tport;
	iargs.max_users = 100;
	
	PLATFORM_IHANDLE = iknow_create(&iargs,  sizeof(iknow_create_args_t));
	if(NULL == PLATFORM_IHANDLE){
		printf("Iknow create error!\n");
		return -1;
	}

	iknow_cmd_init();

	iknow_run(PLATFORM_IHANDLE);

	return 0;
}

#else /* not debug */
int iknow_info_init(void)
{
	return 0;
}
#endif

#ifdef __cplusplus
}
#endif
