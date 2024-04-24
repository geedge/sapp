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
#include "fake_marsio.h"

/*
	在虚拟机, 或CI里无法真正运行marsio驱动测试,
	本文借助fake marsio驱动, 生成一个libgtest_fake_marsio.so, 
	模拟标准marsio接口, 用于测试sapp在marsio模式下的行为是否符合预期.
*/

static void fake_marsio_set_default_env(int mac_flapping_enable)
{
	char vlan_flip_string[256];
	
	set_default_config();
	update_config_file("etc/sapp.toml", "l2_l3_tunnel_support", "1");
	update_config_file("etc/sapp.toml", "overlay_mode", "none");
	update_config_file("etc/sapp.toml", "inject_pkt_mode", "default");
	update_config_file_by_lastline("etc/sapp.toml", "packet_io.deployment", "mode", "inline");
	update_config_file_by_lastNline("etc/sapp.toml", "packet_io.internal.interface", 1, "name", "lo"); /* 此处name叫什么名其实无所谓了, 并不是真正从网卡获取数据包 */
	update_config_file_by_lastNline("etc/sapp.toml", "packet_io.internal.interface", 2, "name", "lo"); /* 此处name叫什么名其实无所谓了, 并不是真正从网卡获取数据包 */
	update_config_file_by_lastNline("etc/sapp.toml", "packet_io.internal.interface", 1, "type", "marsio");  
	update_config_file_by_lastNline("etc/sapp.toml", "packet_io.internal.interface", 2, "type", "marsio"); 

	snprintf(vlan_flip_string, sizeof(vlan_flip_string),"%d\t%d\t%d\n", VLAN_UPLINK_ID, VLAN_DOWNLINK_ID, mac_flapping_enable);
	set_default_vlan_flipping_conf(vlan_flip_string);

	update_config_file("etc/sapp.toml", "marsio_library_path", "\\x22.\\x2flib\\x2flibgtest_fake_marsio.so\\x22");

	return;
}


/* vlan fliping 功能测试 */
void fake_marsio_vlan_flipping_run(void)
{	
	fake_marsio_set_default_env(0);

	update_plugin_inf("TCP_ALL", "void_entry"); /* 挂个空插件 */

	set_pcap_dumpfile("for_gtest_only/fake_marsio/tcp_vlan_flip_no_mac_flip.pcap"); /* 回放一个普通tcp包即可, 会在fake marsio fake_marsio_md5_tuple[] 相关检查函数里验证 */
	ASSERT_EQ(file_md5_checksum("dumpfile", "b621d91181eddfe028dab095df530824"), 0);

	call_libsapp_devel_with_args(1, sapp_online_start_args);
}


/* vlan fliping and mac flipping 功能测试 */
void fake_marsio_vlan_flipp_and_mac_flip_run(void)
{
	fake_marsio_set_default_env(1);

	update_plugin_inf("TCP_ALL", "void_entry"); /* 挂个空插件 */

	set_pcap_dumpfile("for_gtest_only/fake_marsio/tcp_vlan_flip_and_mac_flip.pcap"); /* 回放一个普通tcp包即可, 会在fake marsio fake_marsio_md5_tuple[] 相关检查函数里验证 */
	ASSERT_EQ(file_md5_checksum("dumpfile", "5a588633faa677283fa32cd7c5f3cc97"),0);
	
	call_libsapp_devel_with_args(1, sapp_online_start_args);
}



/* vlan fliping and asymmetric mpls 0vs1层 功能测试 */
void fake_marsio_vlan_flipp_and_symmetric_mpls0vs1_run(void)
{
	fake_marsio_set_default_env(1);
	update_plugin_inf("TCP", "fake_marsio_vlan_flipp_and_symmetric_mpls_entry");  
	set_default_asymmetric_presence_layer_conf("mpls[*]\n");
	
	set_pcap_dumpfile("for_gtest_only/mpls/mpls_asymmetric_0vs1.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "50ef8a3004c9460482d8628c8187f533"),0);

	call_libsapp_devel_with_args(1, sapp_online_start_args);
}


/* vlan fliping and asymmetric mpls 1vs2层 功能测试 */
void fake_marsio_vlan_flipp_and_symmetric_mpls1vs2_run(void)
{
	fake_marsio_set_default_env(1);
	update_plugin_inf("TCP", "fake_marsio_vlan_flipp_and_symmetric_mpls_entry");  
	set_default_asymmetric_presence_layer_conf("mpls[*]\n");

	set_pcap_dumpfile("for_gtest_only/fake_marsio/mpls_asym_1vs2.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "04d5ffa60b959efe7a87ea31fd5fecd9"),0);
	
	call_libsapp_devel_with_args(1, sapp_online_start_args);
}


/* 不开etc/asymmetric_addr_layer.conf->ethernet, 但是开启vlan_flipping和mac_flipping, 注入数据包测试
   模拟K现场模式, 这个测试用例理论上是错误的!
*/

void fake_marsio_vlan_mac_flipping_inject_run(int is_asymmetric)
{
	fake_marsio_set_default_env(1);

	/* 两个测试用例使用一个pcap包, 一个插件, 仅测试是否开启 asymmetric addr时, 不同的结果 */
	if(is_asymmetric){
		set_default_asymmetric_addr_layer_conf("ethernet[*]\nvlan[*]\nmpls[*]\ngre[*]\ngtp[*]\n\n"); /* 启用asymmetric addr */
	}else{
		set_default_asymmetric_addr_layer_conf("\n"); /* 不启用asymmetric addr */
	}
	update_plugin_inf("TCP", "fake_marsio_inject_tcp_entry");

	set_pcap_dumpfile("for_gtest_only/fake_marsio/tcp_inject_vlan_mac_flip.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "777460d92d1b4e98ee22cd14139fa772"),0);

	call_libsapp_devel_with_args(1, sapp_online_start_args);
}

