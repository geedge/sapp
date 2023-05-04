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
#include <gtest/gtest.h>

/*
	测试插件kill_other和kill_follow返回值功能:
	按挂载顺序分为三种:
		master挂载到第一位, 中间位置和最后一位;
	按流状态分为两种:
		master在pending状态返回kill_other或kill_follow;
		master在data状态返回kill_other或kill_follow;

	以上情况总计12种测试用例, 命名规范: kill---[插件返回值]---[master相对位置]---[在opstate哪个状态执行]
		kill_follow_head_pending,
		kill_follow_head_data,
		kill_follow_middle_pending,
		kill_follow_middle_data,
		kill_follow_tail_pending,
		kill_follow_tail_data.

		kill_other_head_pending,
		kill_other_head_data,
		kill_other_middle_pending,
		kill_other_middle_data,
		kill_other_tail_pending,
		kill_other_tail_data.		
*/


/* 公共的初始化函数 */
static void app_state_common_init(void)
{
	set_default_config();

	/* 创建插件目录 */
	system("mkdir -p ./plug/business/gtest_sapp_appstate_1");
	system("mkdir -p ./plug/business/gtest_sapp_appstate_2");

	append_project_list_conf("app_state_project", "struct");

	update_plugin_inf_with_options("./plug/business/gtest_sapp_appstate_1", "gtest1", "tcp_app_state_plug1_init", NULL, "TCP", "tcp_app_state_plug1");
	update_plugin_inf_with_options("./plug/business/gtest_sapp_appstate_2", "gtest2", "tcp_app_state_plug2_init", NULL, "TCP", "tcp_app_state_plug2");

	set_pcap_dumpfile("tcp/tcp_simple.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "df138740a6a22ca9c977052f21f7a470"),0);

	system("> /tmp/app_state_plug_init_file"); /* 清空插件初始化计数文件 */
	system("cp -f ./plug/business/gtest_sapp/libgtest_sapp.so ./plug/business/gtest_sapp_appstate_1/");
	system("cp -f ./plug/business/gtest_sapp/libgtest_sapp.so ./plug/business/gtest_sapp_appstate_2/");
}


/*
	插件挂载顺序:
		master
		plug1
		plug2
*/
void app_state_kill_follow_head_pending_run(void)
{
	app_state_common_init();
  
	/* 更新插件conflist, 第一次使用update, 后续使用append */
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/gtest_sapp_appstate_1/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/gtest_sapp_appstate_2/gtest_sapp.inf"); 

	/* 更新gtest.inf */
	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "tcp_app_state_master_init", NULL, "TCP", "as_kill_follow_head_pending");

	call_libsapp_devel_for_dumpfile_topspeed();
}

void app_state_kill_follow_head_pending_dropme_run(void)
{
	app_state_common_init();
  
	/* 更新插件conflist, 第一次使用update, 后续使用append */
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/gtest_sapp_appstate_1/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/gtest_sapp_appstate_2/gtest_sapp.inf"); 

	/* 更新gtest.inf */
	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "tcp_app_state_master_init", "tcp_app_state_master_destroy", "TCP", "as_kill_follow_head_pending_dropme");

	call_libsapp_devel_for_dumpfile_topspeed();
}


/*
	插件挂载顺序:
		plug1
		master
		plug2
*/
void app_state_kill_follow_middle_pending_run(void)
{
	app_state_common_init();
  
  	system("echo ./plug/business/gtest_sapp_appstate_1/gtest_sapp.inf 1 > ./etc/necessary_plug_list.conf");

	/* 更新插件conflist, 第一次使用update, 后续使用append */
	update_conflist_inf("./plug/business/gtest_sapp_appstate_1/gtest_sapp.inf");
	append_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/gtest_sapp_appstate_2/gtest_sapp.inf"); 

	/* 更新gtest.inf */
	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "tcp_app_state_master_init", NULL, "TCP", "as_kill_follow_middle_pending");

	call_libsapp_devel_for_dumpfile_topspeed();
}

/*
	插件挂载顺序:
		plug1
		plug2
		master
*/
void app_state_kill_follow_tail_pending_run(void)
{
	app_state_common_init();
  
  	system("echo ./plug/business/gtest_sapp_appstate_1/gtest_sapp.inf 1 > ./etc/necessary_plug_list.conf");
  	system("echo ./plug/business/gtest_sapp_appstate_2/gtest_sapp.inf 1 >> ./etc/necessary_plug_list.conf");
	/* 更新插件conflist, 第一次使用update, 后续使用append */
	update_conflist_inf("./plug/business/gtest_sapp_appstate_1/gtest_sapp.inf");
	append_conflist_inf("./plug/business/gtest_sapp_appstate_2/gtest_sapp.inf");
	append_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	/* 更新gtest.inf */
	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "tcp_app_state_master_init", NULL, "TCP", "as_kill_follow_tail_pending");

	call_libsapp_devel_for_dumpfile_topspeed();
}

void app_state_kill_follow_head_data_run(void)
{
	app_state_common_init();
  
	/* 更新插件conflist, 第一次使用update, 后续使用append */
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/gtest_sapp_appstate_1/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/gtest_sapp_appstate_2/gtest_sapp.inf"); 

	/* 更新gtest.inf */
	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "tcp_app_state_master_init", NULL, "TCP", "as_kill_follow_head_data");

	call_libsapp_devel_for_dumpfile_topspeed();
}

void app_state_kill_follow_head_data_dropme_run(void)
{
	app_state_common_init();
  
	/* 更新插件conflist, 第一次使用update, 后续使用append */
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/gtest_sapp_appstate_1/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/gtest_sapp_appstate_2/gtest_sapp.inf"); 

	/* 更新gtest.inf */
	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "tcp_app_state_master_init", "tcp_app_state_master_destroy", "TCP", "as_kill_follow_head_data_dropme");

	call_libsapp_devel_for_dumpfile_topspeed();
}


void app_state_kill_follow_middle_data_run(void)
{
	app_state_common_init();
  
  	system("echo ./plug/business/gtest_sapp_appstate_1/gtest_sapp.inf 1 > ./etc/necessary_plug_list.conf");

	/* 更新插件conflist, 第一次使用update, 后续使用append */
	update_conflist_inf("./plug/business/gtest_sapp_appstate_1/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/gtest_sapp_appstate_2/gtest_sapp.inf"); 

	/* 更新gtest.inf */
	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "tcp_app_state_master_init", NULL, "TCP", "as_kill_follow_middle_data");

	call_libsapp_devel_for_dumpfile_topspeed();
}


void app_state_kill_follow_tail_data_run(void)
{
	app_state_common_init();
  
  	system("echo ./plug/business/gtest_sapp_appstate_1/gtest_sapp.inf 1 > ./etc/necessary_plug_list.conf");
  	system("echo ./plug/business/gtest_sapp_appstate_2/gtest_sapp.inf 1 >> ./etc/necessary_plug_list.conf");
	/* 更新插件conflist, 第一次使用update, 后续使用append */
	update_conflist_inf("./plug/business/gtest_sapp_appstate_1/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/gtest_sapp_appstate_2/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	/* 更新gtest.inf */
	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "tcp_app_state_master_init", NULL, "TCP", "as_kill_follow_tail_data");

	call_libsapp_devel_for_dumpfile_topspeed();
}

void app_state_kill_other_head_pending_run(void)
{
	app_state_common_init();
  
	/* 更新插件conflist, 第一次使用update, 后续使用append */
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/gtest_sapp_appstate_1/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/gtest_sapp_appstate_2/gtest_sapp.inf"); 

	/* 更新gtest.inf */
	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "tcp_app_state_master_init", NULL, "TCP", "as_kill_other_head_pending");

	call_libsapp_devel_for_dumpfile_topspeed();
}

void app_state_kill_other_middle_pending_run(void)
{
	app_state_common_init();
  
	/* 更新插件conflist, 第一次使用update, 后续使用append */
	update_conflist_inf("./plug/business/gtest_sapp_appstate_1/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/gtest_sapp_appstate_2/gtest_sapp.inf"); 

	/* 更新gtest.inf */
	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "tcp_app_state_master_init", NULL, "TCP", "as_kill_other_middle_pending");

	call_libsapp_devel_for_dumpfile_topspeed();
}

void app_state_kill_other_tail_pending_run(void)
{
	app_state_common_init();
  
	/* 更新插件conflist, 第一次使用update, 后续使用append */
	update_conflist_inf("./plug/business/gtest_sapp_appstate_1/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/gtest_sapp_appstate_2/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	/* 更新gtest.inf */
	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "tcp_app_state_master_init", NULL, "TCP", "as_kill_other_tail_pending");

	call_libsapp_devel_for_dumpfile_topspeed();
}

void app_state_kill_other_tail_pending_dropme_run(void)
{
	app_state_common_init();
  
	/* 更新插件conflist, 第一次使用update, 后续使用append */
	update_conflist_inf("./plug/business/gtest_sapp_appstate_1/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/gtest_sapp_appstate_2/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	/* 更新gtest.inf */
	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "tcp_app_state_master_init", "tcp_app_state_master_destroy", "TCP", "as_kill_other_tail_pending_dropme");

	call_libsapp_devel_for_dumpfile_topspeed();
}


void app_state_kill_other_head_data_run(void)
{
	app_state_common_init();
  
	/* 更新插件conflist, 第一次使用update, 后续使用append */
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/gtest_sapp_appstate_1/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/gtest_sapp_appstate_2/gtest_sapp.inf"); 

	/* 更新gtest.inf */
	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "tcp_app_state_master_init", NULL, "TCP", "as_kill_other_head_data");

	call_libsapp_devel_for_dumpfile_topspeed();
}

void app_state_kill_other_middle_data_run(void)
{
	app_state_common_init();
  
	/* 更新插件conflist, 第一次使用update, 后续使用append */
	update_conflist_inf("./plug/business/gtest_sapp_appstate_1/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/gtest_sapp_appstate_2/gtest_sapp.inf"); 

	/* 更新gtest.inf */
	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "tcp_app_state_master_init", NULL, "TCP", "as_kill_other_middle_data");

	call_libsapp_devel_for_dumpfile_topspeed();
}

void app_state_kill_other_tail_data_run(void)
{
	app_state_common_init();
  
	/* 更新插件conflist, 第一次使用update, 后续使用append */
	update_conflist_inf("./plug/business/gtest_sapp_appstate_1/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/gtest_sapp_appstate_2/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	/* 更新gtest.inf */
	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "tcp_app_state_master_init", NULL, "TCP", "as_kill_other_tail_data");

	call_libsapp_devel_for_dumpfile_topspeed();
}


void app_state_kill_follow_ip_entry_run(void)
{
	app_state_common_init();
  
	/* 更新插件conflist, 第一次使用update, 后续使用append */
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/gtest_sapp_appstate_1/gtest_sapp.inf"); 
	append_conflist_inf("./plug/business/gtest_sapp_appstate_2/gtest_sapp.inf"); 
	
	/* 更新gtest.inf */
	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "tcp_app_state_master_init", NULL, "IP", "as_ip_plug_master");
	update_plugin_inf_with_options("./plug/business/gtest_sapp_appstate_1", "gtest1", "tcp_app_state_plug1_init", NULL, "IP", "as_ip_plug_1");
	update_plugin_inf_with_options("./plug/business/gtest_sapp_appstate_2", "gtest2", "tcp_app_state_plug2_init", NULL, "IP", "as_ip_plug_2");

	call_libsapp_devel_for_dumpfile_topspeed();
}


