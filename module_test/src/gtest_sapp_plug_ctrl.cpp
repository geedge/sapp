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

#if SAPP_V4


/*
	pcap就三个包, 三次调用业务插件, 分别是:
	SESSION_STATE_PENDING|SESSION_STATE_DATA,
	SESSION_STATE_DATA,
	SESSION_STATE_DATA|SESSION_STATE_CLOSE
*/
void plug_ctrl_simple_run(void)
{
  set_default_config();

  /* 虚构一个GTEST_PROTOCOL层的协议解析层插件 */
  system("mkdir -p plug/protocol/gtest_protocol");

  append_entry_list("GTEST_PROTOCOL");

  insert_into_conflist_inf("protocol", "./plug/protocol/gtest_protocol/gtest_sapp.inf");

  update_protocol_plugin_inf("./plug/protocol/gtest_protocol", "GTEST_PROTOCOL", "flag_change_protocol_init", 
							"protocol_flag_get_plugid", "protocol_flag_change", "protocol_flag_stat",
  							"UDP", "protocol_state_pd_d_dc_entry");

  /* 注册一个 GTEST_PROTOCOL 层的业务插件 */
  update_plugin_inf("GTEST_PROTOCOL", "flag_change_biz_entry");  
  update_plugin_inf_with_options("./plug/business/gtest_sapp", "flag_change_biz", "flag_change_biz_init", "plut_ctrl_biz_destroy", "GTEST_PROTOCOL", "plugctrl_biz_simple_entry");
  append_project_list_conf("flag_change", "int");
	
  set_pcap_dumpfile("for_gtest_only/plugctrl/udp_3_pkt.pcap");
  
  ASSERT_EQ(file_md5_checksum("dumpfile", "ee39b7b8ce7461340c0bc73378b61d37"),0);

  system("cp -f ./plug/business/gtest_sapp/libgtest_sapp.so ./plug/protocol/gtest_protocol/");

  call_libsapp_devel_with_args(2, sapp_start_args);
}


/*
	pcap就一个包, 同时输出三个状态, 调用业务插件.
*/
void plug_ctrl_3state_pdc_run(void)
{
  set_default_config();

  /* 虚构一个GTEST_PROTOCOL层的协议解析层插件 */
  system("mkdir -p plug/protocol/gtest_protocol");
  append_entry_list("GTEST_PROTOCOL");

  insert_into_conflist_inf("protocol", "./plug/protocol/gtest_protocol/gtest_sapp.inf");

  update_protocol_plugin_inf("./plug/protocol/gtest_protocol", "GTEST_PROTOCOL", "flag_change_protocol_init", 
							"protocol_flag_get_plugid", "protocol_flag_change", "protocol_flag_stat",
  							"UDP", "protocol_3state_pdc_entry");

  /* 注册一个 GTEST_PROTOCOL 层的业务插件 */
  update_plugin_inf("GTEST_PROTOCOL", "flag_change_biz_entry");  
  update_plugin_inf_with_options("./plug/business/gtest_sapp", "flag_change_biz", "flag_change_biz_init", "plut_ctrl_biz_destroy", "GTEST_PROTOCOL", "biz_3state_pdc_entry");
  append_project_list_conf("flag_change", "int");
	
  set_pcap_dumpfile("for_gtest_only/plugctrl/udp_1_pkt.pcap");
  
  ASSERT_EQ(file_md5_checksum("dumpfile", "84a52c541ddce600d811e8b7988a947a"),0);

  system("cp -f ./plug/business/gtest_sapp/libgtest_sapp.so ./plug/protocol/gtest_protocol/");

	call_libsapp_devel_with_args(2, sapp_start_args);  
}


/*
	pcap就两个包, 同时输出两个状态, 调用业务插件, 分别是:
	SESSION_STATE_PENDING|SESSION_STATE_DATA
	SESSION_STATE_DATA|SESSION_STATE_CLOSE
*/
void plug_ctrl_2state_pd_dc_run(void)
{
  set_default_config();

  /* 虚构一个GTEST_PROTOCOL层的协议解析层插件 */
  system("mkdir -p plug/protocol/gtest_protocol");
  append_entry_list("GTEST_PROTOCOL");

  insert_into_conflist_inf("protocol", "./plug/protocol/gtest_protocol/gtest_sapp.inf");

  update_protocol_plugin_inf("./plug/protocol/gtest_protocol", "GTEST_PROTOCOL", "flag_change_protocol_init", 
							"protocol_flag_get_plugid", "protocol_flag_change", "protocol_flag_stat",
  							"UDP", "protocol_2state_pd_dc_entry");

  /* 注册一个 GTEST_PROTOCOL 层的业务插件 */
  update_plugin_inf("GTEST_PROTOCOL", "flag_change_biz_entry");  
  update_plugin_inf_with_options("./plug/business/gtest_sapp", "flag_change_biz", "flag_change_biz_init", "plut_ctrl_biz_destroy", "GTEST_PROTOCOL", "biz_2state_pd_dc_entry");
  append_project_list_conf("flag_change", "int");
	
  set_pcap_dumpfile("for_gtest_only/plugctrl/udp_2_pkt.pcap");
  
  ASSERT_EQ(file_md5_checksum("dumpfile", "60902faeb56fba3de750391658b07309"),0);

  system("cp ./plug/business/gtest_sapp/libgtest_sapp.so ./plug/protocol/gtest_protocol/");

	call_libsapp_devel_with_args(2, sapp_start_args);  
}


/*
	pcap就三个包, 三次调用业务插件, 分别是:
	SESSION_STATE_PENDING|SESSION_STATE_DATA,
	SESSION_STATE_DATA,
	SESSION_STATE_DATA|SESSION_STATE_CLOSE
*/
void plug_ctrl_state_pd_d_dc_run(void)
{
  set_default_config();

  /* 虚构一个GTEST_PROTOCOL层的协议解析层插件 */
  system("mkdir -p plug/protocol/gtest_protocol");
  append_entry_list("GTEST_PROTOCOL");

  insert_into_conflist_inf("protocol", "./plug/protocol/gtest_protocol/gtest_sapp.inf");

  update_protocol_plugin_inf("./plug/protocol/gtest_protocol", "GTEST_PROTOCOL", "flag_change_protocol_init", 
							"protocol_flag_get_plugid", "protocol_flag_change", "protocol_flag_stat",
  							"UDP", "protocol_state_pd_d_dc_entry");

  /* 注册一个 GTEST_PROTOCOL 层的业务插件 */
  update_plugin_inf("GTEST_PROTOCOL", "flag_change_biz_entry");  
  update_plugin_inf_with_options("./plug/business/gtest_sapp", "flag_change_biz", "flag_change_biz_init", "plut_ctrl_biz_destroy", "GTEST_PROTOCOL", "biz_state_pd_d_dc_entry");
  append_project_list_conf("flag_change", "int");
	
  set_pcap_dumpfile("for_gtest_only/plugctrl/udp_3_pkt.pcap");
  
  ASSERT_EQ(file_md5_checksum("dumpfile", "ee39b7b8ce7461340c0bc73378b61d37"),0);

  system("cp ./plug/business/gtest_sapp/libgtest_sapp.so ./plug/protocol/gtest_protocol/");

	call_libsapp_devel_with_args(2, sapp_start_args);  
}

/*
	测试插件在pending状态下返回dropme.
*/
void plug_ctrl_biz_dropme_in_pending_run(void)
{
  set_default_config();

  /* 虚构一个GTEST_PROTOCOL层的协议解析层插件 */
  system("mkdir -p plug/protocol/gtest_protocol");
  append_entry_list("GTEST_PROTOCOL");

  insert_into_conflist_inf("protocol", "./plug/protocol/gtest_protocol/gtest_sapp.inf");

  update_protocol_plugin_inf("./plug/protocol/gtest_protocol", "GTEST_PROTOCOL", "flag_change_protocol_init", 
							"protocol_flag_get_plugid", "protocol_flag_change", "protocol_flag_stat",
  							"UDP", "protocol_push_3state_entry");

  /* 注册一个 GTEST_PROTOCOL 层的业务插件 */
  update_plugin_inf("GTEST_PROTOCOL", "flag_change_biz_entry");  
  update_plugin_inf_with_options("./plug/business/gtest_sapp", "flag_change_biz", "flag_change_biz_init", "plut_ctrl_biz_destroy", "GTEST_PROTOCOL", "biz_dropme_in_pending_state_entry");
  append_project_list_conf("flag_change", "int");
	
  set_pcap_dumpfile("for_gtest_only/plugctrl/udp_3_pkt.pcap");
  
  ASSERT_EQ(file_md5_checksum("dumpfile", "ee39b7b8ce7461340c0bc73378b61d37"),0);

  system("cp ./plug/business/gtest_sapp/libgtest_sapp.so ./plug/protocol/gtest_protocol/");

	call_libsapp_devel_with_args(2, sapp_start_args);  
}


/*
	测试插件在data状态下返回dropme.
*/
void plug_ctrl_biz_dropme_in_data_run(void)
{
  set_default_config();

  /* 虚构一个GTEST_PROTOCOL层的协议解析层插件 */
  system("mkdir -p plug/protocol/gtest_protocol");
  append_entry_list("GTEST_PROTOCOL");

  insert_into_conflist_inf("protocol", "./plug/protocol/gtest_protocol/gtest_sapp.inf");

  update_protocol_plugin_inf("./plug/protocol/gtest_protocol", "GTEST_PROTOCOL", "flag_change_protocol_init", 
							"protocol_flag_get_plugid", "protocol_flag_change", "protocol_flag_stat",
  							"UDP", "protocol_push_3state_entry");

  /* 注册一个 GTEST_PROTOCOL 层的业务插件 */
  update_plugin_inf("GTEST_PROTOCOL", "flag_change_biz_entry");  
  update_plugin_inf_with_options("./plug/business/gtest_sapp", "flag_change_biz", "flag_change_biz_init", "plut_ctrl_biz_destroy", "GTEST_PROTOCOL", "biz_dropme_in_data_state_entry");
  append_project_list_conf("flag_change", "int");
	
  set_pcap_dumpfile("for_gtest_only/plugctrl/udp_3_pkt.pcap");
  
  ASSERT_EQ(file_md5_checksum("dumpfile", "ee39b7b8ce7461340c0bc73378b61d37"),0);

  system("cp ./plug/business/gtest_sapp/libgtest_sapp.so ./plug/protocol/gtest_protocol/");

  call_libsapp_devel_with_args(2, sapp_start_args);
}

/*
	测试插件在close状态下返回dropme.
*/
void plug_ctrl_biz_dropme_in_close_run(void)
{
  set_default_config();

  /* 虚构一个GTEST_PROTOCOL层的协议解析层插件 */
  system("mkdir -p plug/protocol/gtest_protocol");
  append_entry_list("GTEST_PROTOCOL");

  insert_into_conflist_inf("protocol", "./plug/protocol/gtest_protocol/gtest_sapp.inf");

  update_protocol_plugin_inf("./plug/protocol/gtest_protocol", "GTEST_PROTOCOL", "flag_change_protocol_init", 
							"protocol_flag_get_plugid", "protocol_flag_change", "protocol_flag_stat",
  							"UDP", "protocol_push_3state_entry");

  /* 注册一个 GTEST_PROTOCOL 层的业务插件 */
  update_plugin_inf("GTEST_PROTOCOL", "flag_change_biz_entry");  
  update_plugin_inf_with_options("./plug/business/gtest_sapp", "flag_change_biz", "flag_change_biz_init", "plut_ctrl_biz_destroy", "GTEST_PROTOCOL", "biz_dropme_in_close_state_entry");
  append_project_list_conf("flag_change", "int");
	
  set_pcap_dumpfile("for_gtest_only/plugctrl/udp_3_pkt.pcap");
  
  ASSERT_EQ(file_md5_checksum("dumpfile", "ee39b7b8ce7461340c0bc73378b61d37"),0);

  system("cp ./plug/business/gtest_sapp/libgtest_sapp.so ./plug/protocol/gtest_protocol/");

  call_libsapp_devel_with_args(2, sapp_start_args);
}


/*
	测试插件在close状态下返回giveme.
*/
void plug_ctrl_biz_giveme_in_close_run(void)
{
  set_default_config();

  /* 虚构一个GTEST_PROTOCOL层的协议解析层插件 */
  system("mkdir -p plug/protocol/gtest_protocol");
  append_entry_list("GTEST_PROTOCOL");

  insert_into_conflist_inf("protocol", "./plug/protocol/gtest_protocol/gtest_sapp.inf");

  update_protocol_plugin_inf("./plug/protocol/gtest_protocol", "GTEST_PROTOCOL", "flag_change_protocol_init", 
							"protocol_flag_get_plugid", "protocol_flag_change", "protocol_flag_stat",
  							"UDP", "protocol_push_close_state_entry");

  /* 注册一个 GTEST_PROTOCOL 层的业务插件 */
  update_plugin_inf("GTEST_PROTOCOL", "flag_change_biz_entry");  
  update_plugin_inf_with_options("./plug/business/gtest_sapp", "flag_change_biz", "flag_change_biz_init", "plut_ctrl_biz_destroy", "GTEST_PROTOCOL", "biz_giveme_in_close_state_entry");
  append_project_list_conf("flag_change", "int");
	
  set_pcap_dumpfile("for_gtest_only/plugctrl/udp_3_pkt.pcap");
  
  ASSERT_EQ(file_md5_checksum("dumpfile", "ee39b7b8ce7461340c0bc73378b61d37"),0);

  system("cp ./plug/business/gtest_sapp/libgtest_sapp.so ./plug/protocol/gtest_protocol/");

	call_libsapp_devel_with_args(2, sapp_start_args);  
}


/*
	测试flag 转换函数,
	之前某个bug是因为一个插件挂载不成功, 导致协议解析层的flag_change函数没被调用,
	被误认为是所有插件都不关心任何字段, 导致功能不正常.
*/
void plug_ctrl_flag_change_run(void)
{
  set_default_config();

  /* 虚构一个GTEST_PROTOCOL层的协议解析层插件 */
  system("mkdir -p plug/protocol/gtest_protocol");
  append_entry_list("GTEST_PROTOCOL");

  insert_into_conflist_inf("protocol", "./plug/protocol/gtest_protocol/gtest_sapp.inf");

  update_protocol_plugin_inf("./plug/protocol/gtest_protocol", "GTEST_PROTOCOL", "flag_change_protocol_init", 
							"protocol_flag_get_plugid", "protocol_flag_change", "protocol_flag_stat",
  							"TCP", "flag_change_protocol_tcp_entry");

  /* 注册一个 GTEST_PROTOCOL 层的业务插件 */
  update_plugin_inf("GTEST_PROTOCOL", "flag_change_biz_entry");  
  update_plugin_inf_with_options("./plug/business/gtest_sapp", "flag_change_biz", "flag_change_biz_init", NULL, "GTEST_PROTOCOL", "flag_change_biz_entry");

  /* 注意!!!! 此处故意注册一个不存在的插件, 让插件管理出现错误. */
  append_conflist_inf("./plug/business/error/error.inf");

  append_project_list_conf("flag_change", "int");

  set_pcap_dumpfile("tcp/tcp_simple.pcap");
  
  ASSERT_EQ(file_md5_checksum("dumpfile", "df138740a6a22ca9c977052f21f7a470"),0);

  system("cp ./plug/business/gtest_sapp/libgtest_sapp.so ./plug/protocol/gtest_protocol/");

	call_libsapp_devel_with_args(2, sapp_start_args);  
}


static void update_wire_graft_config_file(void)
{
#define SAMPLE_WIRE_GRAFT_CONFIG "[record_link_info]\nstream_project_tag_enable=1\nat_least_total_num=2\nat_least_total_byte=10\nidentification_by_which_device=lo\nmirror_mode_enable=1\nmirror_linkinfo_project_name=mirror_linkinfo_from_mac\n[toroad]\nsendto_toroad_enable=0\ntoroad_ip=192.168.40.134\ntoroad_port=8888\n[log]\nlog_level=30"

	system("mkdir -p ./etc/wire_graft");

	FILE *fp = fopen("etc/wire_graft/wire_graft.conf", "w+");
	if(NULL == fp){
		return;
	}

	fprintf(fp, "%s\n", SAMPLE_WIRE_GRAFT_CONFIG);

	fclose(fp);
}

/*
	wire_graft插件需要抽取底层链路信息, 读取了sapp的内部私有结构体, 如果发布的版本不一致, 是加载不了的,
	此处仅用于测试发布到yum仓库的wire_graft是否能加载成功.
*/
void special_plug_wire_graft_test(void)
{
	set_default_config();

	update_plugin_inf("TCP", "special_plug_wire_graft_check_entry");
	append_conflist_inf("./plug/platform/wire_graft/wire_graft.inf");

	update_wire_graft_config_file();
	
	set_pcap_dumpfile("tcp/tcp_simple.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "df138740a6a22ca9c977052f21f7a470"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);  

}


#endif

