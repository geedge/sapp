#include "sapp_api.h"
#include "sapp_private_api.h"
#include "MESA/field_stat2.h"

static screen_stat_handle_t g_sapp_fs2_handle;

int packet_io_status_mesafs_init(void)
{
	int opt;
	
	g_sapp_fs2_handle = FS_create_handle();

	FS_set_para(g_sapp_fs2_handle, OUTPUT_DEVICE, "./sapp_fs2_stat.log", strlen("./sapp_fs2_stat.log"));
	opt = 1;
	FS_set_para(g_sapp_fs2_handle, PRINT_MODE, &opt, sizeof(int));

	opt = 1;
	FS_set_para(g_sapp_fs2_handle, CREATE_THREAD, &opt, sizeof(int));

	opt = 1;
	FS_set_para(g_sapp_fs2_handle, STAT_CYCLE, &opt, sizeof(int));


	return 0;
}

