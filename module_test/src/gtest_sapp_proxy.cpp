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
#include <sys/types.h>	 
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include "gtest_sapp_fun.h"
#include <gtest/gtest.h>


/*
	读一个包, 故意伪装成代理协议, 用于测试sapp和解析层处理代理协议的正确性.

	对于数据包fake_proxy.pcap:
	    fake proxy协议解析层跳过前面的"11111111111111111111111", 剥去后继续调用deal_tcp_in_proxy_stream().
	    业务插件收到的是"11111111111111111111111"后面的"dfgsdfg"等数据.
*/
void sapp_deal_proxy_run(void)
{
	set_default_config();
	
	/* 虚构一个KAFE_PROXY层的协议解析层插件 */
	system("mkdir -p plug/protocol/gtest_fake_proxy");
	append_entry_list("FAKE_PROXY");
	insert_into_conflist_inf("protocol", "./plug/protocol/gtest_fake_proxy/gtest_sapp.inf");
	update_protocol_plugin_inf("./plug/protocol/gtest_fake_proxy", "FAKE_PROXY", "gtest_sapp_slave_init", 
							  "protocol_flag_get_plugid", "protocol_flag_change", "protocol_flag_stat",
							  "TCP", "proxy_protocol_tcp_entry");
	/* 注册一个 FAKE_PROXY 层的业务插件 */
	update_plugin_inf("TCP", "proxy_business_tcp_entry");  

	system("cp ./plug/business/gtest_sapp/libgtest_sapp.so ./plug/protocol/gtest_fake_proxy/");
	
	set_pcap_dumpfile("for_gtest_only/proxy/fake_proxy.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "e8fee0162317007dd332b26188277665"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}


void sapp_deal_proxy_kill_tcp_run(void)
{
	set_default_config();
	/* 虚构一个KAFE_PROXY层的协议解析层插件 */
	system("mkdir -p plug/protocol/gtest_fake_proxy");
	append_entry_list("FAKE_PROXY");
	insert_into_conflist_inf("protocol", "./plug/protocol/gtest_fake_proxy/gtest_sapp.inf");
	
	update_protocol_plugin_inf("./plug/protocol/gtest_fake_proxy", "FAKE_PROXY", "gtest_sapp_slave_init", 
							  "protocol_flag_get_plugid", "protocol_flag_change", "protocol_flag_stat",
							  "TCP", "proxy_protocol_tcp_entry");
	/* 注册一个 FAKE_PROXY 层的业务插件 */
	update_plugin_inf("TCP", "proxy_business_kill_tcp_entry");  

	system("cp ./plug/business/gtest_sapp/libgtest_sapp.so ./plug/protocol/gtest_fake_proxy/");
	
	set_pcap_dumpfile("for_gtest_only/proxy/fake_proxy.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "e8fee0162317007dd332b26188277665"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}


