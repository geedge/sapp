#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>
#include "stream.h"
#include <sys/types.h>			/* See NOTES */
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include "gtest_sapp_fun.h"

typedef struct{
	int plug_entry_times[4];
}app_state_stat_t;

static int app_state_project_id = -1;
static app_state_stat_t *g_app_state_stat = NULL; /* 在返回DROPME的测试用例中, 在插件ENTRY层面无法再统计后续的计数, 将其保存在全局变量中, 在destroy中检查计数 */
static char (*g_check_stat_before_exit)(void); /* destory函数中调用的计数检查函数指针 */


static int __check_all_plug_has_inited(void)
{
	FILE *fp;
	char buf[100];
	int ret = 0;

	fp = popen("cat /tmp/app_state_plug_init_file | wc -l", "r");
	if(NULL == fp){
		return -1;
	}

	fgets(buf, sizeof(buf), fp);

	if(strncasecmp("3", buf, 1) == 0){
		ret = 0;
	}else{
		ret = -1;
	}

	pclose(fp);

	return ret;
}

static app_state_stat_t *app_state_get_struct(struct streaminfo *pstream)
{
	app_state_stat_t *ptr = (app_state_stat_t *)project_req_get_struct(pstream, app_state_project_id);

	if(NULL == ptr){
		ptr = (app_state_stat_t *)calloc(1, sizeof(app_state_stat_t));
		project_req_add_struct(pstream, app_state_project_id, ptr);
	}

	return ptr;
}


static char as_check_result_follow_head_pending(struct streaminfo *pstream)
{
	app_state_stat_t *pstat = app_state_get_struct(pstream);

	pstat->plug_entry_times[0]++;
	
	if(__check_all_plug_has_inited() != 0){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "app_state_follow_head_pending", "\033[1;31;40mtest app state follow_head_pending error, some plug has init failed!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	/* 46个带负载的数据包, 最后一次为CLOSE */
	if(47 != pstat->plug_entry_times[0]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "app_state_follow_head_pending","\033[1;31;40mtest follow_head_pending error, plug_master number is not 47!!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	/* 后续的插件都不应该被调用 */
	if(0 != pstat->plug_entry_times[1]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "app_state_follow_head_pending","\033[1;31;40mtest follow_head_pending error, plug1 number is not zeor!!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}
	
	if(0 != pstat->plug_entry_times[2]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "app_state_follow_head_pending","\033[1;31;40mtest follow_head_pending error, plug2 number is not zeor!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	SAPP_PLUG_LOG(RLOG_LV_FATAL, "app_state_follow_head_pending","\033[32mtest follow_head_pending success!\033[0m\n");
	gtest_set_libsapp_devel_result(GTEST_SAPP_SUCC);	

	return APP_STATE_DROPME;
}

static char as_check_result_follow_head_pending_dropme(void)
{
	
	if(__check_all_plug_has_inited() != 0){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "app_state_follow_head_pending_dropme","\033[1;31;40mtest app state kill_follow error, some plug has init failed!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	/* pending被master插件kill,不会被调用 */
	if(0 != g_app_state_stat->plug_entry_times[1]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "app_state_follow_head_pending_dropme","\033[1;31;40mtest kill_follow error, plug1 number is %d, expect 0!\033[0m\n", g_app_state_stat->plug_entry_times[1]);
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	/* pending被master插件kill,不会被调用 */
	if(0 != g_app_state_stat->plug_entry_times[2]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "app_state_follow_head_pending_dropme","\033[1;31;40mtest kill_follow error, plug2 number is %d, expect 0!\033[0m\n", g_app_state_stat->plug_entry_times[1]);
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	SAPP_PLUG_LOG(RLOG_LV_INFO, "app_state_follow_head_pending_dropme","\033[32mtest follow_head_pending_dropme success!\033[0m\n");
	gtest_set_libsapp_devel_result(GTEST_SAPP_SUCC);	

	return APP_STATE_DROPME;
}


static char as_check_result_follow_middle_pending(struct streaminfo *pstream)
{
	app_state_stat_t *pstat = app_state_get_struct(pstream);

	pstat->plug_entry_times[0]++;
	
	if(__check_all_plug_has_inited() != 0){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "app_state_follow_middle_pending","\033[1;31;40mtest app state kill_follow error, some plug has init failed!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	/* 46个带负载的数据包, 最后一次为CLOSE */
	if(47 != pstat->plug_entry_times[0]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "app_state_follow_middle_pending","\033[1;31;40mtest kill_follow error, plug_master number is not 47!!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	if(pstat->plug_entry_times[0] != pstat->plug_entry_times[1]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "app_state_follow_middle_pending","\033[1;31;40mtest kill_follow error, master and plug1 number is not equal!!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}
	
	if(0 != pstat->plug_entry_times[2]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "app_state_follow_middle_pending","\033[1;31;40mtest kill_follow error, plug2 number is not zeor!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	SAPP_PLUG_LOG(RLOG_LV_INFO, "app_state_follow_middle_pending","\033[32mtest result_follow_middle_pending success!\033[0m\n");
	gtest_set_libsapp_devel_result(GTEST_SAPP_SUCC);	

	return APP_STATE_DROPME;
}

static char as_check_result_follow_tail_pending(struct streaminfo *pstream)
{
	app_state_stat_t *pstat = app_state_get_struct(pstream);
	
	pstat->plug_entry_times[0]++;
	
	if(__check_all_plug_has_inited() != 0){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "follow_tail_pending","\033[1;31;40mtest app state kill_follow error, some plug has init failed!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	/* 46个带负载的数据包, 最后一次为CLOSE */
	if(47 != pstat->plug_entry_times[0]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "follow_tail_pending","\033[1;31;40mtest kill_follow error, plug_master number is not 47!!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	if(pstat->plug_entry_times[0] != pstat->plug_entry_times[1]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "follow_tail_pending","\033[1;31;40mtest kill_follow error, master and plug1 number is not equal!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}
	
	if(pstat->plug_entry_times[0] != pstat->plug_entry_times[2]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "follow_tail_pending","\033[1;31;40mtest kill_follow error, master and plug2 number is not equal!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	SAPP_PLUG_LOG(RLOG_LV_INFO, "follow_tail_pending","\033[32mtest follow_tail_pending success!\033[0m\n");
	gtest_set_libsapp_devel_result(GTEST_SAPP_SUCC);	

	return APP_STATE_DROPME;
}

static char as_check_result_follow_head_data(struct streaminfo *pstream)
{
	app_state_stat_t *pstat = app_state_get_struct(pstream);
	
	pstat->plug_entry_times[0]++;
	
	if(__check_all_plug_has_inited() != 0){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "follow_head_data","\033[1;31;40mtest app state kill_follow error, some plug has init failed!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	/* 46个带负载的数据包, 最后一次为CLOSE */
	if(47 != pstat->plug_entry_times[0]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "follow_head_data","\033[1;31;40mtest kill_follow error, plug_master number is not 47!!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}	

	if(2 != pstat->plug_entry_times[1]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "follow_head_data","\033[1;31;40mtest kill_follow error, plug1 number is not 2!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}
	
	if(2 != pstat->plug_entry_times[2]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "follow_head_data","\033[1;31;40mtest kill_follow error, plug2 number is not 2!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	SAPP_PLUG_LOG(RLOG_LV_FATAL, "follow_head_data","\033[32mtest follow_head_data success!\033[0m\n");
	gtest_set_libsapp_devel_result(GTEST_SAPP_SUCC);	

	return APP_STATE_DROPME;
}

static char as_check_result_follow_head_data_dropme(void)
{
	
	if(__check_all_plug_has_inited() != 0){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "follow_head_data_dropme","\033[1;31;40mtest app state kill_follow error, some plug has init failed!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	/* pending调用一次, data被master插件kill, close最后调用一次 */
	if(2 != g_app_state_stat->plug_entry_times[1]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "follow_head_data_dropme","\033[1;31;40mtest kill_follow error, plug1 number is %d, expect 1!\033[0m\n", g_app_state_stat->plug_entry_times[1]);
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	/* pending调用一次, data被master插件kill, close最后调用一次 */
	if(2 != g_app_state_stat->plug_entry_times[2]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "follow_head_data_dropme","\033[1;31;40mtest kill_follow error, plug2 number is %d, expect 1!\033[0m\n", g_app_state_stat->plug_entry_times[1]);
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	SAPP_PLUG_LOG(RLOG_LV_INFO, "follow_head_data_dropme","\033[32mtest follow_head_data_dropme success!\033[0m\n");
	gtest_set_libsapp_devel_result(GTEST_SAPP_SUCC);	

	return APP_STATE_DROPME;
}


static char as_check_result_follow_middle_data(struct streaminfo *pstream)
{
	app_state_stat_t *pstat = app_state_get_struct(pstream);
	
	pstat->plug_entry_times[0]++;
	
	if(__check_all_plug_has_inited() != 0){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "follow_middle_data","\033[1;31;40mtest app state kill_follow error, some plug has init failed!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	if(pstat->plug_entry_times[0] != pstat->plug_entry_times[1]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "follow_middle_data","\033[1;31;40mtest kill_follow error, master and plug1 number is not equal!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}
	
	if(2 != pstat->plug_entry_times[2]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "follow_middle_data","\033[1;31;40mtest kill_follow error, plug2 number is not 2!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	SAPP_PLUG_LOG(RLOG_LV_FATAL, "follow_middle_data","\033[32mtest follow_middle_data success!\033[0m\n");
	gtest_set_libsapp_devel_result(GTEST_SAPP_SUCC);	

	return APP_STATE_DROPME;
}

/* 放在最后的kill_follow其实没什么作用, 所有插件的计数都应该一样 */
static char as_check_result_follow_tail_data(struct streaminfo *pstream)
{
	app_state_stat_t *pstat = app_state_get_struct(pstream);
	
	pstat->plug_entry_times[0]++;
	
	if(__check_all_plug_has_inited() != 0){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "follow_tail_data","\033[1;31;40mtest app state kill_follow error, some plug has init failed!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	/* 46个带负载的数据包, 最后一次为CLOSE */
	if(47 != pstat->plug_entry_times[0]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "follow_tail_data","\033[1;31;40mtest kill_follow error, plug_master number is not 47!!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	if(pstat->plug_entry_times[0] != pstat->plug_entry_times[1]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "follow_tail_data","\033[1;31;40mtest kill_follow error, master and plug1 number is not equal!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}
	
	if(pstat->plug_entry_times[0] != pstat->plug_entry_times[2]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "follow_tail_data","\033[1;31;40mtest kill_follow error, master and plug1 number is not equal!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	SAPP_PLUG_LOG(RLOG_LV_FATAL, "follow_tail_data","\033[32mtest follow_tail_data success!\033[0m\n");
	gtest_set_libsapp_devel_result(GTEST_SAPP_SUCC);	

	return APP_STATE_DROPME;
}

static char as_check_result_other_head_pending(struct streaminfo *pstream)
{
	/* 复用kill_follow的结果, 是一致的 */
	return as_check_result_follow_head_pending(pstream);
}

static char as_check_result_other_middle_pending(struct streaminfo *pstream)
{
	app_state_stat_t *pstat = app_state_get_struct(pstream);

	pstat->plug_entry_times[0]++;
	
	if(__check_all_plug_has_inited() != 0){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "other_middle_pending","\033[1;31;40mtest app state kill_follow error, some plug has init failed!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}


	/* 46个带负载的数据包, 最后一次为CLOSE */
	if(47 != pstat->plug_entry_times[0]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "other_middle_pending","\033[1;31;40mtest kill_follow error, plug_master number is not 47!!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	if(2 != pstat->plug_entry_times[1]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "other_middle_pending","\033[1;31;40mtest kill_follow error, plug1 number is not 2!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}
	
	if(0 != pstat->plug_entry_times[2]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "other_middle_pending","\033[1;31;40mtest kill_follow error, plug2 number is not zeor!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	SAPP_PLUG_LOG(RLOG_LV_FATAL, "other_middle_pending","\033[32mtest other_middle_pending success!\033[0m\n");
	gtest_set_libsapp_devel_result(GTEST_SAPP_SUCC);	

	return APP_STATE_DROPME;
}

static char as_check_result_other_tail_pending(struct streaminfo *pstream)
{
	app_state_stat_t *pstat = app_state_get_struct(pstream);

	pstat->plug_entry_times[0]++;
	
	if(__check_all_plug_has_inited() != 0){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "other_tail_pending","\033[1;31;40mtest app state kill_follow error, some plug has init failed!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}


	/* 46个带负载的数据包, 最后一次为CLOSE */
	if(47 != pstat->plug_entry_times[0]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "other_tail_pending","\033[1;31;40mtest kill_follow error, plug_master number is not 47!!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	if(2 != pstat->plug_entry_times[1]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "other_tail_pending","\033[1;31;40mtest kill_follow error, plug1 number is not 2!!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}
	
	if(2 != pstat->plug_entry_times[2]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "other_tail_pending","\033[1;31;40mtest kill_follow error, plug2 number is not 2!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	SAPP_PLUG_LOG(RLOG_LV_FATAL, "other_tail_pending","\033[32mtest kill_follow success!\033[0m\n");
	gtest_set_libsapp_devel_result(GTEST_SAPP_SUCC);	

	return APP_STATE_DROPME;
}

static char as_check_result_other_tail_pending_dropme(void)
{
	if(__check_all_plug_has_inited() != 0){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "tail_pending_dropme","\033[1;31;40mtest app state kill_follow error, some plug has init failed!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	/* pending调用一次, close最后调用一次 */
	if(2 != g_app_state_stat->plug_entry_times[1]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "tail_pending_dropme","\033[1;31;40mtest kill_follow error, plug1 number is %d, expect 1!\033[0m\n", g_app_state_stat->plug_entry_times[1]);
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	/* pending调用一次, close最后调用一次 */
	if(2 != g_app_state_stat->plug_entry_times[2]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "tail_pending_dropme","\033[1;31;40mtest kill_follow error, plug2 number is %d, expect 1!\033[0m\n", g_app_state_stat->plug_entry_times[1]);
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	SAPP_PLUG_LOG(RLOG_LV_INFO, "tail_pending_dropme","\033[32mtest tail_pending_dropme success!\033[0m\n");
	gtest_set_libsapp_devel_result(GTEST_SAPP_SUCC);	

	return APP_STATE_DROPME;
}


static char as_check_result_other_head_data(struct streaminfo *pstream)
{
	app_state_stat_t *pstat = app_state_get_struct(pstream);
	
	pstat->plug_entry_times[0]++;
	
	if(__check_all_plug_has_inited() != 0){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "other_head_data","\033[1;31;40mtest app state kill_follow error, some plug has init failed!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}


	/* 46个带负载的数据包, 最后一次为CLOSE */
	if(47 != pstat->plug_entry_times[0]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "other_head_data","\033[1;31;40mtest kill_follow error, plug_master number is not 47!!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}
	

	if(2 != pstat->plug_entry_times[1]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "other_head_data","\033[1;31;40mtest kill_follow error, plug1 number is not 3!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}
	
	if(2 != pstat->plug_entry_times[2]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "other_head_data","\033[1;31;40mtest kill_follow error, plug2 number is not 2!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	SAPP_PLUG_LOG(RLOG_LV_INFO, "other_head_data","\033[32mtest other_head_data success!\033[0m\n");
	gtest_set_libsapp_devel_result(GTEST_SAPP_SUCC);	

	return APP_STATE_DROPME;
}


static char as_check_result_other_middle_data(struct streaminfo *pstream)
{
	app_state_stat_t *pstat = app_state_get_struct(pstream);

	pstat->plug_entry_times[0]++;
	
	if(__check_all_plug_has_inited() != 0){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "other_middle_data","\033[1;31;40mtest app state kill_follow error, some plug has init failed!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	/* 46个带负载的数据包, 最后一次为CLOSE */
	if(47 != pstat->plug_entry_times[0]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "other_middle_data","\033[1;31;40mtest kill_follow error, plug_master number is not 47!!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	if(3 != pstat->plug_entry_times[1]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "other_middle_data","\033[1;31;40mtest kill_follow error, plug1 number is not 3!!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}
	
	if(2 != pstat->plug_entry_times[2]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "other_middle_data","\033[1;31;40mtest kill_follow error, plug2 number is not 2!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	SAPP_PLUG_LOG(RLOG_LV_INFO, "other_middle_data","\033[32mtest other_middle_data success!\033[0m\n");
	gtest_set_libsapp_devel_result(GTEST_SAPP_SUCC);	

	return APP_STATE_DROPME;
}

static char as_check_result_other_tail_data(struct streaminfo *pstream)
{
	app_state_stat_t *pstat = app_state_get_struct(pstream);

	pstat->plug_entry_times[0]++;
	
	if(__check_all_plug_has_inited() != 0){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "other_tail_data","\033[1;31;40mtest app state kill_follow error, some plug has init failed!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}


	/* 46个带负载的数据包, 最后一次为CLOSE */
	if(47 != pstat->plug_entry_times[0]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "other_tail_data","\033[1;31;40mtest kill_follow error, plug_master number is not 47!!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}
	

	if(3 != pstat->plug_entry_times[1]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "other_tail_data","\033[1;31;40mtest kill_follow error, plug1 number is not 3!!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}
	
	if(3 != pstat->plug_entry_times[2]){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "other_tail_data","\033[1;31;40mtest kill_follow error, plug2 number is not 3!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	SAPP_PLUG_LOG(RLOG_LV_INFO, "other_tail_data","\033[32mtest other_tail_data success!\033[0m\n");
	gtest_set_libsapp_devel_result(GTEST_SAPP_SUCC);	

	return APP_STATE_DROPME;
}


static char as_common_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet, char kill_type,int pending_state, char return_value)
{
	char ret = 0;
	app_state_stat_t *pstat = app_state_get_struct(pstream);

	pstat->plug_entry_times[0]++;

	if(OP_STATE_PENDING == pstream->opstate){
		if(1 == pending_state){
			ret = return_value | kill_type;
		}else{
			ret = APP_STATE_GIVEME; /* 不符合state条件默认返回GIVEME */
		}
	}else{
		if(0 == pending_state){
			ret = return_value | kill_type;
		}else{
			ret = APP_STATE_GIVEME; /* 不符合state条件默认返回GIVEME */
		}
	}

	return ret;
}


extern "C" char as_kill_follow_head_pending(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	char ret;
	if(OP_STATE_CLOSE == pstream->opstate){
		ret = as_check_result_follow_head_pending(pstream);
	}else{
		ret= as_common_entry(pstream, pme, thread_seq, a_packet, APP_STATE_KILL_FOLLOW, 1, APP_STATE_GIVEME);
	}

	return ret;
}

extern "C" char as_kill_follow_head_pending_dropme(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	if(OP_STATE_PENDING == pstream->opstate){
		g_app_state_stat = app_state_get_struct(pstream);
		g_check_stat_before_exit = &as_check_result_follow_head_pending_dropme;
	}

	return as_common_entry(pstream, pme, thread_seq, a_packet, APP_STATE_KILL_FOLLOW, 1, APP_STATE_DROPME);
}


extern "C" char as_kill_follow_middle_pending(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	char ret;
	
	if(OP_STATE_CLOSE == pstream->opstate){
		ret = as_check_result_follow_middle_pending(pstream);
	}else{
		ret = as_common_entry(pstream, pme, thread_seq, a_packet, APP_STATE_KILL_FOLLOW, 1, APP_STATE_GIVEME);
	}

	return ret;
}

extern "C" char as_kill_follow_tail_pending(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	char ret;
	
	if(OP_STATE_CLOSE == pstream->opstate){
		ret = as_check_result_follow_tail_pending(pstream);
	}else{
		ret = as_common_entry(pstream, pme, thread_seq, a_packet, APP_STATE_KILL_FOLLOW, 1, APP_STATE_GIVEME);
	}

	return ret;
}

extern "C" char as_kill_follow_head_data(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	char ret;
	
	if(OP_STATE_CLOSE == pstream->opstate){
		ret = as_check_result_follow_head_data(pstream);
	}else{
		ret = as_common_entry(pstream, pme, thread_seq, a_packet, APP_STATE_KILL_FOLLOW, 0, APP_STATE_GIVEME);
	}
	return ret;
}

extern "C" char as_kill_follow_head_data_dropme(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	if(OP_STATE_PENDING == pstream->opstate){
		g_app_state_stat = app_state_get_struct(pstream);
		g_check_stat_before_exit = &as_check_result_follow_head_data_dropme;
	}

	return as_common_entry(pstream, pme, thread_seq, a_packet, APP_STATE_KILL_FOLLOW, 0, APP_STATE_DROPME);
}


extern "C" char as_kill_follow_middle_data(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	char ret;
	if(OP_STATE_CLOSE == pstream->opstate){
		ret = as_check_result_follow_middle_data(pstream);
	}else{
		ret = as_common_entry(pstream, pme, thread_seq, a_packet, APP_STATE_KILL_FOLLOW, 0, APP_STATE_GIVEME);
	}
	return ret;
}

extern "C" char as_kill_follow_tail_data(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	char ret;
	if(OP_STATE_CLOSE == pstream->opstate){
		ret = as_check_result_follow_tail_data(pstream);
	}else{
		ret = as_common_entry(pstream, pme, thread_seq, a_packet, APP_STATE_KILL_FOLLOW, 0, APP_STATE_GIVEME);
	}
	return ret;
}


extern "C" char as_kill_other_head_pending(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	char ret;
	if(OP_STATE_CLOSE == pstream->opstate){
		ret = as_check_result_other_head_pending(pstream);
	}else{
		ret = as_common_entry(pstream, pme, thread_seq, a_packet, APP_STATE_KILL_OTHER, 1, APP_STATE_GIVEME);
	}
	return ret;
}

extern "C" char as_kill_other_middle_pending(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	char ret;
	int rand_num = rand();
	
	if(OP_STATE_CLOSE == pstream->opstate){
		ret = as_check_result_other_middle_pending(pstream);
	}else{
		/* 因为是kill_other, 返回DROPPKT不影响其他插件, 随机测试一下返回DROPPKT是否正常 */
		if(rand_num & 1){
			return as_common_entry(pstream, pme, thread_seq, a_packet, APP_STATE_KILL_OTHER, 1, APP_STATE_GIVEME|APP_STATE_DROPPKT);
		}
		
		ret = as_common_entry(pstream, pme, thread_seq, a_packet, APP_STATE_KILL_OTHER, 1, APP_STATE_GIVEME);
	}

	return ret;
}


extern "C" char as_kill_other_tail_pending(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	char ret;
	if(OP_STATE_CLOSE == pstream->opstate){
		ret = as_check_result_other_tail_pending(pstream);
	}else{
		ret = as_common_entry(pstream, pme, thread_seq, a_packet, APP_STATE_KILL_OTHER, 1, APP_STATE_GIVEME);
	}
	return ret;
}

extern "C" char as_kill_other_tail_pending_dropme(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	if(OP_STATE_PENDING == pstream->opstate){
		g_app_state_stat = app_state_get_struct(pstream);
		g_check_stat_before_exit = &as_check_result_other_tail_pending_dropme;
	}

	return as_common_entry(pstream, pme, thread_seq, a_packet, APP_STATE_KILL_OTHER, 1, APP_STATE_DROPME);
}


extern "C" char as_kill_other_head_data(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int rand_num = rand();
	char ret;
	
	if(OP_STATE_CLOSE == pstream->opstate){
		ret = as_check_result_other_head_data(pstream);
	}else{
		/* 因为是kill_other, 返回DROPPKT不影响其他插件, 随机测试一下返回DROPPKT是否正常 */
		if(rand_num & 1){
			return as_common_entry(pstream, pme, thread_seq, a_packet, APP_STATE_KILL_OTHER, 0, APP_STATE_GIVEME|APP_STATE_DROPPKT);
		}	
		ret = as_common_entry(pstream, pme, thread_seq, a_packet, APP_STATE_KILL_OTHER, 0, APP_STATE_GIVEME);
	}

	return ret;
}

extern "C" char as_kill_other_middle_data(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int rand_num = rand();
	char ret;
	
	if(OP_STATE_CLOSE == pstream->opstate){
		ret = as_check_result_other_middle_data(pstream);
	}else{
		/* 因为是kill_other, 返回DROPPKT不影响其他插件, 随机测试一下返回DROPPKT是否正常 */
		if(rand_num & 1){
			return as_common_entry(pstream, pme, thread_seq, a_packet, APP_STATE_KILL_OTHER, 0, APP_STATE_GIVEME|APP_STATE_DROPPKT);
		}
		
		ret = as_common_entry(pstream, pme, thread_seq, a_packet, APP_STATE_KILL_OTHER, 0, APP_STATE_GIVEME);
	}

	return ret;
}

extern "C" char as_kill_other_tail_data(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	char ret;
	
	if(OP_STATE_CLOSE == pstream->opstate){
		ret = as_check_result_other_tail_data(pstream);
	}else{
		ret = as_common_entry(pstream, pme, thread_seq, a_packet, APP_STATE_KILL_OTHER, 0, APP_STATE_GIVEME);
	}
	return ret;
}


static void app_state_project_req_free_cb(int thread_seq, void *project_req_value)
{
	/* 此处故意不free内存, 因为exit之前会清空所有流结构体, 在tcp_app_state_master_destroy里计数统计就不对了 */
	return;
}

extern "C" int tcp_app_state_master_init(void)
{
	if(gtest_sapp_slave_init() < 0){
		return -1;
	}
	app_state_project_id = project_producer_register("app_state_project", "struct", app_state_project_req_free_cb);
	assert(app_state_project_id >= 0);

	system("echo master >> /tmp/app_state_plug_init_file");

	return 0;
}

extern "C" void tcp_app_state_master_destroy(void)
{
	if(g_check_stat_before_exit){
		g_check_stat_before_exit();
	}
}

extern "C" int tcp_app_state_plug1_init(void)
{
	app_state_project_id = project_producer_register("app_state_project", "struct", app_state_project_req_free_cb);
	assert(app_state_project_id >= 0);

	system("echo 1 >> /tmp/app_state_plug_init_file");

	printf("app_state_plug1_init, app_state_project_id=%d\n", app_state_project_id);
	
	return 0;
}

extern "C" char tcp_app_state_plug1(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	app_state_stat_t *pstat = app_state_get_struct(pstream);
	
	pstat->plug_entry_times[1]++; /* slave插件不论什么状态下都先加计数, 表示被调用过 */

	if(OP_STATE_PENDING == pstream->opstate){
		*pme = malloc(1000); /* 模拟一般插件行为 */
		memset(*pme, 0xAA, 1000);
	}
	
	if(OP_STATE_CLOSE == pstream->opstate){
		memset(*pme, 0xFE, 1000);
		free(*pme);
	}	
	
	return APP_STATE_GIVEME;
}

extern "C" int tcp_app_state_plug2_init(void)
{
	app_state_project_id = project_producer_register("app_state_project", "struct", app_state_project_req_free_cb);
	assert(app_state_project_id >= 0);

	system("echo 2 >> /tmp/app_state_plug_init_file");

	printf("app_state_plug2_init, app_state_project_id=%d\n", app_state_project_id);
	
	return 0;
}

extern "C" char tcp_app_state_plug2(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	app_state_stat_t *pstat = app_state_get_struct(pstream);
	
	pstat->plug_entry_times[2]++; /* slave插件不论什么状态下都先加计数, 表示被调用过 */

	if(OP_STATE_PENDING == pstream->opstate){
		*pme = malloc(1000); /* 模拟一般插件行为 */
		memset(*pme, 0xAA, 1000);
	}
	
	if(OP_STATE_CLOSE == pstream->opstate){
		memset(*pme, 0xFE, 1000);
		free(*pme);
	}	
	
	return APP_STATE_GIVEME;
}

extern "C" char as_ip_plug_master(const struct streaminfo *pstream,unsigned char routedir,int thread_seq, const void *ipv4_hdr)
{
	static int __ip_pkt_num = 0;

	if(__ip_pkt_num++ > 60){
		SAPP_PLUG_LOG(RLOG_LV_INFO, "ip_plug","\033[32mtest kill_follow ip entry succ!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_SUCC);	
	}
	return APP_STATE_GIVEME | APP_STATE_KILL_FOLLOW;
}

extern "C" char as_ip_plug_1(const struct streaminfo *pstream,unsigned char routedir,int thread_seq, const void *ipv4_hdr)
{
	/* master返回KILL_FOLLOW, plug_1不应该受到任何包 */
	SAPP_PLUG_LOG(RLOG_LV_FATAL, "ip_plug1","\033[1;31;40mtest app state ip entry error, ip plug1 has recv pkt!\033[0m\n");
	gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);

	return APP_STATE_GIVEME;
}

extern "C" char as_ip_plug_2(const struct streaminfo *pstream,unsigned char routedir,int thread_seq, const void *ipv4_hdr)
{
	/* master返回KILL_FOLLOW, plug_2不应该受到任何包 */
	SAPP_PLUG_LOG(RLOG_LV_FATAL, "ip_plug2","\033[1;31;40mtest app state ip entry error, ip plug2 has recv pkt!\033[0m\n");
	gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);

	return APP_STATE_GIVEME;
}



