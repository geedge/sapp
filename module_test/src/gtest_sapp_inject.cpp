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
    sapp包注入测试:
    原理: 使用特殊IP地址的pcap包作为dumpfile, 保证和任何常见网络ip不冲突, 比如保留IP段, 169.254/16,
          创建一个tun/tap虚拟设备, 将其IP设为169.254/16段, 
          发包时会自动路由到tun/tap设备上, 捕包分析sapp发出去的包是否符合预期.
*/


#if 0 /* 改成用sapp_benchmark框架测试, 不需要写代码重新编译 */
void MESA_rst_tcp_test_v4_run(void)
{
	set_default_config();
  
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "MESA_rst_tcp_test_init_v4", NULL, "TCP", "MESA_rst_tcp_plug_entry");

#if SAPP_V3
	update_config_file("conf/main.conf", "CreatLinkMode", "1");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "syn_mandatory", "1");
	update_config_file("etc/sapp.toml", "inject_pkt_mode", "sys_route");
#else
	abort();
#endif

	set_pcap_dumpfile("for_gtest_only/inject/tcp_rst_packet_sample.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "6be85f33b5eba93fd184bcecf27e41ae"),0);
	
	gtest_start_sapp_progress(sapp_start_args);
}


void MESA_rst_tcp_test_v6_run(void)
{
	set_default_config();
  
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "MESA_rst_tcp_test_init_v6", NULL, "TCP", "MESA_rst_tcp_plug_entry");

#if SAPP_V3
		update_config_file("conf/main.conf", "CreatLinkMode", "1");
#elif SAPP_V4
		update_config_file("etc/sapp.toml", "syn_mandatory", "1");
		update_config_file("etc/sapp.toml", "inject_pkt_mode", "sys_route");
#else
		abort();
#endif

	set_pcap_dumpfile("for_gtest_only/inject/tcp_rst_packet_sample_v6.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "e2a9db40450ac0853103d3dc423ba027"),0);
	
	gtest_start_sapp_progress(sapp_start_args);
}
#endif


void MESA_rst_tcp_with_vlan_single_c2s_run(void)
{
	set_default_config();
  
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "MESA_rst_tcp_test_init_v4", "gtest_sapp_inject_plug_destory", "TCP", "MESA_rst_tcp_plug_c2s_entry");

#if SAPP_V3
	update_config_file("conf/main.conf", "CreatLinkMode", "1");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "inject_pkt_mode", "raw_ethernet_single_gateway");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_device", "tap0");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_src_mac", "00:11:22:33:44:55");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_dst_mac", "00:11:22:33:44:66");
#else
	abort();
#endif
	update_config_file("etc/sapp.toml", "skip_not_ip_layer_over_eth", "0");

	set_pcap_dumpfile("for_gtest_only/inject/tcp_rst_with_vlan_single_c2s.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "a2bf72d3f73142e80de77657c61f62d5"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}


void MESA_rst_tcp_with_vlan_pppoe_run(void)
{
	set_default_config();
  
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "MESA_rst_tcp_test_init_v4", "gtest_sapp_inject_plug_destory", "TCP", "MESA_rst_tcp_plug_c2s_entry");

#if SAPP_V3
	update_config_file("conf/main.conf", "CreatLinkMode", "1");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "inject_pkt_mode", "raw_ethernet_single_gateway");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_device", "tap0");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_src_mac", "00:11:22:33:44:55");	
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_dst_mac", "00:11:22:33:44:66");
#else
	abort();
#endif
	update_config_file("etc/sapp.toml", "skip_not_ip_layer_over_eth", "0");

	set_pcap_dumpfile("for_gtest_only/inject/tcp_rst_with_vlan_pppoe.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "9d531337eec3c38c7336cd38ddec296e"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}


void MESA_rst_tcp_with_mpls_1vs2_run(void)

{
	set_default_config();
  
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "MESA_rst_tcp_test_init_v4", "gtest_sapp_inject_plug_destory", "TCP", "MESA_rst_tcp_plug_entry_in_double_dir");

#if SAPP_V3
	update_config_file("conf/main.conf", "CreatLinkMode", "1");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "inject_pkt_mode", "raw_ethernet_single_gateway");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_device", "tap0");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_src_mac", "00:11:22:33:44:55");	
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_dst_mac", "00:11:22:33:44:66");
#else
	abort();
#endif
	update_config_file("etc/sapp.toml", "skip_not_ip_layer_over_eth", "0");

	set_pcap_dumpfile("for_gtest_only/inject/tcp_rst_with_mpls_asymmetric_1vs2.pcap");

	set_default_asymmetric_addr_layer_conf("ethernet[*]\nvlan[*]\nmpls[*]\ngre[*]\ngtp[*]\n\n");
	set_default_asymmetric_presence_layer_conf("mpls ethernet[0] ipv4[1]\nmpls ethernet[1] ipv4[2]\n\n");

	ASSERT_EQ(file_md5_checksum("dumpfile", "00765a14b12a6551904be00b54f2189c"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}


void MESA_rst_tcp_with_mpls_0vs2_run(void)
{
	set_default_config();
  
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "MESA_rst_tcp_test_init_v4", "gtest_sapp_inject_plug_destory", "TCP", "MESA_rst_tcp_plug_entry_in_double_dir");

#if SAPP_V3
	update_config_file("conf/main.conf", "CreatLinkMode", "1");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "inject_pkt_mode", "raw_ethernet_single_gateway");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_device", "tap0");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_src_mac", "00:11:22:33:44:55");	
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_dst_mac", "00:11:22:33:44:66");
	update_config_file("etc/sapp.toml", "create_mpls_anyway", "1");
#else
	abort();
#endif
	update_config_file("etc/sapp.toml", "skip_not_ip_layer_over_eth", "0");

	set_pcap_dumpfile("for_gtest_only/inject/tcp_rst_with_mpls_asymmetric_0vs2.pcap");

	set_default_asymmetric_addr_layer_conf("ethernet[*]\nvlan[*]\nmpls[*]\ngre[*]\ngtp[*]\n\n");
	set_default_asymmetric_presence_layer_conf("mpls ethernet[0] ipv4[1]\nmpls ethernet[1] ipv4[2]\n\n");

	ASSERT_EQ(file_md5_checksum("dumpfile", "104bf4131fa138429d8dbccafed71ba5"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}

void MESA_rst_tcp_with_mpls_single_c2s_run(void)
{
	set_default_config();
  
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "MESA_rst_tcp_test_init_v4", "gtest_sapp_inject_plug_destory", "TCP", "MESA_rst_tcp_plug_c2s_entry");

#if SAPP_V3
	update_config_file("conf/main.conf", "CreatLinkMode", "1");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "inject_pkt_mode", "raw_ethernet_single_gateway");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_device", "tap0");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_src_mac", "00:11:22:33:44:55");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_dst_mac", "00:11:22:33:44:66");
#else
	abort();
#endif

	set_pcap_dumpfile("for_gtest_only/inject/tcp_rst_with_mpls_single_c2s.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "5fb19164daeb5e665047f45d88890b0a"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}



void MESA_rst_tcp_with_vpls_run(void)
{
	set_default_config();
  
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "MESA_rst_tcp_test_init_v4", "gtest_sapp_inject_plug_destory", "TCP", "MESA_rst_tcp_plug_entry_in_double_dir");

#if SAPP_V3
	update_config_file("conf/main.conf", "CreatLinkMode", "1");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "inject_pkt_mode", "raw_ethernet_single_gateway");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_device", "tap0");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_src_mac", "00:11:22:33:44:55");	
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_dst_mac", "00:11:22:33:44:66");
	update_config_file("etc/sapp.toml", "create_mpls_anyway", "1");
#else
	abort();
#endif
	update_config_file("etc/sapp.toml", "skip_not_ip_layer_over_eth", "0");

	set_pcap_dumpfile("for_gtest_only/inject/tcp_rst_with_vpls.pcap");

	set_default_asymmetric_addr_layer_conf("ethernet[*]\nvlan[*]\nmpls[*]\ngre[*]\ngtp[*]\n\n");
	set_default_asymmetric_presence_layer_conf("mpls ethernet[0] ipv4[1]\nmpls ethernet[1] ipv4[2]\n\n");

	ASSERT_EQ(file_md5_checksum("dumpfile", "e4357ef2933e139bea72d0f77e6b0d96"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}


void MESA_rst_tcp_with_double_vlan_run(void)
{
	set_default_config();
  
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "MESA_rst_tcp_test_init_v4", "gtest_sapp_inject_plug_destory", "TCP", "MESA_rst_tcp_plug_entry_in_double_dir");

#if SAPP_V3
	update_config_file("conf/main.conf", "CreatLinkMode", "1");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "inject_pkt_mode", "raw_ethernet_single_gateway");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_device", "tap0");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_src_mac", "00:11:22:33:44:55");	
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_dst_mac", "00:11:22:33:44:66");
#else
	abort();
#endif
	update_config_file("etc/sapp.toml", "skip_not_ip_layer_over_eth", "0");

	set_pcap_dumpfile("for_gtest_only/inject/tcp_rst_with_double_vlan.pcap");

	set_default_asymmetric_addr_layer_conf("ethernet[*]\nvlan[*]\nmpls[*]\ngre[*]\ngtp[*]\n\n");
	set_default_asymmetric_presence_layer_conf("mpls ethernet[0] ipv4[1]\nmpls ethernet[1] ipv4[2]\n\n");

	ASSERT_EQ(file_md5_checksum("dumpfile", "d4c5e09bba97e72cbc6f04f64439a624"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}


void MESA_rst_tcp_with_8021ad_qinq_run(void)
{
	set_default_config();
  
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "MESA_rst_tcp_test_init_v4", "gtest_sapp_inject_plug_destory", "TCP", "MESA_rst_tcp_plug_c2s_entry");

#if SAPP_V3
	update_config_file("conf/main.conf", "CreatLinkMode", "1");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "inject_pkt_mode", "raw_ethernet_single_gateway");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_device", "tap0");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_src_mac", "00:11:22:33:44:55");	
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_dst_mac", "00:11:22:33:44:66");
#else
	abort();
#endif
	update_config_file("etc/sapp.toml", "skip_not_ip_layer_over_eth", "0");

	set_pcap_dumpfile("vlan/QinQ_with_http.pcap");

	set_default_asymmetric_addr_layer_conf("ethernet[*]\nvlan[*]\nmpls[*]\ngre[*]\ngtp[*]\n\n");
	set_default_asymmetric_presence_layer_conf("mpls ethernet[0] ipv4[1]\nmpls ethernet[0] ipv6[1]\n\n");

	ASSERT_EQ(file_md5_checksum("dumpfile", "76b4545432085c74817411bb1ecf450f"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}


void MESA_rst_tcp_mpls_vlan_mpls_c2s_run(void)
{
	set_default_config();
  
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "MESA_rst_tcp_test_init_v4", "gtest_sapp_inject_plug_destory", "TCP", "MESA_rst_tcp_plug_s2c_entry");

#if SAPP_V3
	update_config_file("conf/main.conf", "CreatLinkMode", "1");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "inject_pkt_mode", "raw_ethernet_single_gateway");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_device", "tap0");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_src_mac", "00:11:22:33:44:55");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_dst_mac", "00:11:22:33:44:66");
#else
	abort();
#endif
	update_config_file("etc/sapp.toml", "skip_not_ip_layer_over_eth", "0");
	
	set_pcap_dumpfile("for_gtest_only/inject/tcp_rst_mpls_vlan_mpls_mxpe_s2c.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "29589eeca441438807e7606f7006e9e7"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}


void MESA_kill_tcp_test_v4_run(void)
{
	set_default_config();
  
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "MESA_rst_tcp_test_init_v4", "gtest_sapp_inject_plug_destory", "TCP", "MESA_kill_tcp_plug_entry_in_double_dir");

#if SAPP_V3
	update_config_file("conf/main.conf", "CreatLinkMode", "1");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "number", "1");
	update_config_file("etc/sapp.toml", "auto_remedy", "0");
	update_config_file("etc/sapp.toml", "inject_pkt_mode", "sys_route");
#else
	abort();
#endif

	set_pcap_dumpfile("for_gtest_only/inject/tcp_rst_packet_sample.pcap");

	set_default_asymmetric_addr_layer_conf("ethernet[*]\nvlan[*]\nmpls[*]\ngre[*]\ngtp[*]\n\n");
	set_default_asymmetric_presence_layer_conf("mpls ethernet[0] ipv4[1]\nmpls ethernet[1] ipv4[2]\n\n");

	ASSERT_EQ(file_md5_checksum("dumpfile", "6be85f33b5eba93fd184bcecf27e41ae"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}


void sapp_inject_tcp_payload_test_v4_run(void)
{
	set_default_config();
  
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "MESA_rst_tcp_test_init_v4", "gtest_sapp_inject_plug_destory", "TCP", "sapp_inject_tcp_payload_c2s");

#if SAPP_V3
	update_config_file("conf/main.conf", "CreatLinkMode", "1");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "number", "1");
	update_config_file("etc/sapp.toml", "auto_remedy", "0");
	update_config_file("etc/sapp.toml", "inject_pkt_mode", "raw_ethernet_single_gateway");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_device", "tap0");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_src_mac", "00:11:22:33:44:55");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_dst_mac", "00:11:22:33:44:66");

#else
	abort();
#endif

	set_pcap_dumpfile("tcp/tcp_simple.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "df138740a6a22ca9c977052f21f7a470"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}

void MESA_inject_tcp_payload_test_v4_run(void)
{
	set_default_config();
  
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "MESA_rst_tcp_test_init_v4", "gtest_sapp_inject_plug_destory", "TCP", "MESA_inject_tcp_payload_c2s");

#if SAPP_V3
	update_config_file("conf/main.conf", "CreatLinkMode", "1");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "number", "1");
	update_config_file("etc/sapp.toml", "auto_remedy", "0");
	update_config_file("etc/sapp.toml", "inject_pkt_mode", "raw_ethernet_single_gateway");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_device", "tap0");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_src_mac", "00:11:22:33:44:55");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_dst_mac", "00:11:22:33:44:66");	
#else
	abort();
#endif

	set_pcap_dumpfile("tcp/tcp_simple.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "df138740a6a22ca9c977052f21f7a470"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}


void sapp_inject_tcp_payload_test_v6_run(void)
{
	set_default_config();
  
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "MESA_rst_tcp_test_init_v6", "gtest_sapp_inject_plug_destory", "TCP", "sapp_inject_tcp_payload_s2c");

#if SAPP_V3
		update_config_file("conf/main.conf", "CreatLinkMode", "1");
#elif SAPP_V4
		update_config_file("etc/sapp.toml", "syn_mandatory", "1");
		update_config_file("etc/sapp.toml", "inject_pkt_mode", "raw_ethernet_single_gateway");
		update_config_file("etc/sapp.toml", "inject_mode_single_gateway_device", "tap0");
		update_config_file("etc/sapp.toml", "inject_mode_single_gateway_src_mac", "00:11:22:33:44:55");
		update_config_file("etc/sapp.toml", "inject_mode_single_gateway_dst_mac", "00:11:22:33:44:66"); 
#else
		abort();
#endif

	set_pcap_dumpfile("for_gtest_only/inject/tcp_inject_payload_v6.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "9e97e5d633a4ae4a66dc17020ccf726a"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}



void MESA_inject_udp_mpls_vlan_mpls_s2c_run(void)
{
	set_default_config();
  
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "MESA_rst_tcp_test_init_v4", "gtest_sapp_inject_plug_destory", "UDP", "MESA_inject_udp_plug_s2c_entry");

#if SAPP_V3
	update_config_file("conf/main.conf", "CreatLinkMode", "1");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "inject_pkt_mode", "raw_ethernet_single_gateway");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_device", "tap0");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_src_mac", "00:11:22:33:44:55");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_dst_mac", "00:11:22:33:44:66");
#else
	abort();
#endif
	update_config_file("etc/sapp.toml", "skip_not_ip_layer_over_eth", "0");

	set_pcap_dumpfile("for_gtest_only/inject/udp_mpls_vlan_mpls_mxpe_s2c.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "502e5d3fbcce730493175a491c7102a6"), 0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}


/* 
	pcap包: tcp_asymmetric_mpls_vlan_mpls_mxpe_double.pcap, 
	从底向上分别是: ethernet->mpls->ethernet->vlan->mpls->ipv4->tcp
*/
void sapp_inject_tcp_mpls_vlan_mpls_asymmetric_double_run(void)
{
	set_default_config();
  
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "MESA_rst_tcp_test_init_v4", "gtest_sapp_inject_plug_destory", "TCP", "MESA_rst_tcp_plug_entry_in_double_dir");

#if SAPP_V3
	update_config_file("conf/main.conf", "CreatLinkMode", "1");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "inject_pkt_mode", "raw_ethernet_single_gateway");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_device", "tap0");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_src_mac", "00:11:22:33:44:55");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_dst_mac", "00:11:22:33:44:66");
#else
	abort();
#endif
	update_config_file("etc/sapp.toml", "skip_not_ip_layer_over_eth", "0");

	set_pcap_dumpfile("for_gtest_only/inject/tcp_asymmetric_mpls_vlan_mpls_mxpe_double.pcap");

	set_default_asymmetric_addr_layer_conf("ethernet[*]\nvlan[*]\nmpls[*]\ngre[*]\ngtp[*]\n\n");
	set_default_asymmetric_presence_layer_conf("mpls ethernet[0] ipv4[1]\nmpls ethernet[1] ipv4[2]\n\n");

	ASSERT_EQ(file_md5_checksum("dumpfile", "98755901f48760e6a5e23fd41b21dd91"), 0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}


/*
	测试纯ipv4发送rst, 但是为了mpls对齐问题, 构造了虚拟mpls层, 此时发包时应该跳过mpls层, 检查是否正确.
*/
void MESA_rst_tcp_pure_ipv4_with_fake_mpls_run(void)
{
	set_default_config();
  
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "MESA_rst_tcp_test_init_v4", "gtest_sapp_inject_plug_destory", "TCP", "MESA_rst_tcp_plug_entry");

#if SAPP_V3
	update_config_file("conf/main.conf", "CreatLinkMode", "1");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "inject_pkt_mode", "raw_ethernet_single_gateway");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_device", "tap0");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_src_mac", "00:11:22:33:44:55");	
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_dst_mac", "00:11:22:33:44:66");
#else
	abort();
#endif
	update_config_file("etc/sapp.toml", "skip_not_ip_layer_over_eth", "0");

	set_default_asymmetric_addr_layer_conf("ethernet[*]\nvlan[*]\nmpls[*]\ngre[*]\ngtp[*]\n\n");
	set_default_asymmetric_presence_layer_conf("mpls ethernet[0] ipv4[1]\nmpls ethernet[1] ipv4[2]\n\n");

	set_pcap_dumpfile("for_gtest_only/inject/tcp_rst_packet_sample.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "6be85f33b5eba93fd184bcecf27e41ae"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}


/*
	测试并联模式且发包为sys_route的情况下, 配置文件etc/asymmetric_addr_layer.conf, 开启了最底层ethernet之后,
	对于单向流, 无法发送ethernet包的问题.
	实际上, 并联模式加sys_route是不关心最底层ethernet的, 此时asymmetric_addr_layer最底层是无效的, 不关心的,
	不应该影响实际发包功能.
*/
void MESA_rst_tcp_reverse_ethernet_run(void)
{
	set_default_config();
  
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "MESA_rst_tcp_test_init_v4", "gtest_sapp_inject_plug_destory", "TCP", "MESA_rst_tcp_plug_s2c_entry");

#if SAPP_V3
	update_config_file("conf/main.conf", "CreatLinkMode", "1");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "inject_pkt_mode", "sys_route"); /* 此处设为sys_route, 为了让系统路由能发送到tap0, pcap包的ip地址要设成169.254.1.1, 169.254.254.254 */
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_src_mac", "00:11:22:33:44:55");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_dst_mac", "00:11:22:33:44:66");
#else
	abort();
#endif
	/* 故意开启配置ethernet[0], 其实systoue发包不应该关心这个层 */
	set_default_asymmetric_addr_layer_conf("ethernet[0]\n\n");

	set_pcap_dumpfile("for_gtest_only/inject/tcp_rst_reverse_ethernet.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "1ad44ac7f83aeeb73457f43ddbec8b8c"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}


/*
	GTP隧道双向流注入RST包测试.
*/
void sapp_inject_gtp_double_dir_run(void)
{
	set_default_config();
  
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "MESA_rst_tcp_test_init_v4", "gtest_sapp_inject_plug_destory", "TCP", "MESA_rst_tcp_plug_entry");

#if SAPP_V3
	update_config_file("conf/main.conf", "CreatLinkMode", "1");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "inject_pkt_mode", "raw_ethernet_single_gateway");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_device", "tap0");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_src_mac", "00:11:22:33:44:55");	
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_dst_mac", "00:11:22:33:44:66");
#else
	abort();
#endif

	set_default_asymmetric_addr_layer_conf("ethernet[*]\nvlan[*]\nmpls[*]\ngre[*]\ngtp[*]\n\n");

	set_pcap_dumpfile("for_gtest_only/gtp/gtp_double.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "0b1d409dcc3987f55465c4c989da1651"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}


/*
	GTP隧道单向流反向注入包, 开启asymmetric_addr_layer特性,
	由C2S方向的原始包触发, 发送一个S2C方向的rst包, 理论上是要失败的.
*/
void sapp_inject_gtp_single_reverse_asymmetric_run(void)
{
	set_default_config();
  
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "MESA_rst_tcp_test_init_v4", "gtest_sapp_inject_plug_destory", "TCP", "gtp_single_reverse_send_entry");

#if SAPP_V3
	update_config_file("conf/main.conf", "CreatLinkMode", "1");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "inject_pkt_mode", "raw_ethernet_single_gateway");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_device", "tap0");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_src_mac", "00:11:22:33:44:55");	
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_dst_mac", "00:11:22:33:44:66");
#else
	abort();
#endif

	set_default_asymmetric_addr_layer_conf("gtp[*]\n\n");

	set_pcap_dumpfile("for_gtest_only/gtp/gtp_c2s_single.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "826fe4846e9d200b66fff8d10d132097"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}

/*
	GTP隧道单向流反向注入包, 
	不带seq, 不带seq, 不带seq !!!
	不开启asymmetric_addr_layer特性,
	由C2S方向的原始包触发, 发送一个S2C方向的rst包, 理论上是成功的.
*/
void sapp_inject_gtp_single_reverse_not_asymmetric_run(void)
{
	set_default_config();
  
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "MESA_rst_tcp_test_init_v4", "gtest_sapp_inject_plug_destory", "TCP", "MESA_rst_tcp_plug_s2c_entry");

#if SAPP_V3
	update_config_file("conf/main.conf", "CreatLinkMode", "1");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "inject_pkt_mode", "raw_ethernet_single_gateway");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_device", "tap0");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_src_mac", "00:11:22:33:44:55");	
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_dst_mac", "00:11:22:33:44:66");
#else
	abort();
#endif

	set_default_asymmetric_addr_layer_conf("\n");

	set_pcap_dumpfile("for_gtest_only/gtp/gtp_c2s_no_seq_single_no_asymmetric.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "d3603d4b1010c8e32198d9457d1ec2d9"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}

/*
	GTP隧道单向流反向注入包, 
	带seq, 带seq, 带seq !!!
	不开启asymmetric_addr_layer特性,
	由C2S方向的原始包触发, 发送一个S2C方向的rst包, 理论上是成功的.
*/
void sapp_inject_gtp_seq_single_reverse_not_asymmetric_run(void)
{
	set_default_config();
  
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	/* 测试包gtp_c2s_seq_single_no_asymmetric.pcap是个S2C方向的http应答,   触发一个C2S方向的rst */ 
	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "MESA_rst_tcp_test_init_v4", "gtest_sapp_inject_plug_destory", "TCP", "MESA_rst_tcp_plug_c2s_entry");

#if SAPP_V3
	update_config_file("conf/main.conf", "CreatLinkMode", "1");
#elif SAPP_V4
	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "inject_pkt_mode", "raw_ethernet_single_gateway");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_device", "tap0");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_src_mac", "00:11:22:33:44:55");	
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_dst_mac", "00:11:22:33:44:66");
	update_config_file("etc/sapp.toml", "skip_gtp_seq_field_for_inject", "1");
	update_config_file("etc/sapp.toml", "skip_gtp_S_PN_E_field_for_inject", "1");	
#else
	abort();
#endif

	set_default_asymmetric_addr_layer_conf("\n");

	set_pcap_dumpfile("for_gtest_only/gtp/gtp_c2s_seq_single_no_asymmetric.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "fe7bd4457fb5964138424710c3d004d3"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}


/*
	GTP隧道双向流注入带负载的包测试.
*/
void sapp_inject_gtp_payload_double_dir_run(void)
{
	set_default_config();
  
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "MESA_rst_tcp_test_init_v4", "gtest_sapp_inject_plug_destory", "TCP", "inject_gtp_payload_tcp_entry");

	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "inject_pkt_mode", "raw_ethernet_single_gateway");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_device", "tap0");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_src_mac", "00:11:22:33:44:55");	
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_dst_mac", "00:11:22:33:44:66");

	set_default_asymmetric_addr_layer_conf("ethernet[*]\nvlan[*]\nmpls[*]\ngre[*]\ngtp[*]\n\n");

	set_pcap_dumpfile("for_gtest_only/gtp/gtp_double_for_inject_payload.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "6811767abc29be542e9655bd91e94f55"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}


/*
	GTP隧道双向流注入原始IP包测试, 模拟kni插件的行为.
*/
void sapp_inject_gtp_raw_ip_pkt_double_dir_run(void)
{
	set_default_config();
  
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "MESA_rst_tcp_test_init_v4", "gtest_sapp_inject_plug_destory", "TCP", "inject_raw_ip_pkt_tcp_entry");

	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "inject_pkt_mode", "raw_ethernet_single_gateway");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_device", "tap0");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_src_mac", "00:11:22:33:44:55");	
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_dst_mac", "00:11:22:33:44:66");

	set_default_asymmetric_addr_layer_conf("ethernet[*]\nvlan[*]\nmpls[*]\ngre[*]\ngtp[*]\n\n");

	set_pcap_dumpfile("for_gtest_only/gtp/gtp_double_for_inject_payload.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "6811767abc29be542e9655bd91e94f55"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}


/*
	L2TP隧道双向流注入包测试.
*/
void sapp_inject_l2tp_double_dir_run(void)
{
	set_default_config();
  
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "MESA_rst_tcp_test_init_v4", "gtest_sapp_inject_plug_destory", "TCP", "MESA_rst_tcp_plug_entry_in_double_dir");

	update_config_file("etc/sapp.toml", "syn_mandatory", "1");
	update_config_file("etc/sapp.toml", "inject_pkt_mode", "raw_ethernet_single_gateway");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_device", "tap0");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_src_mac", "00:11:22:33:44:55");	
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_dst_mac", "00:11:22:33:44:66");

	set_default_asymmetric_addr_layer_conf("ethernet[*]\nvlan[*]\nmpls[*]\ngre[*]\ngtp[*]\n\n");

	set_pcap_dumpfile("for_gtest_only/inject/tcp_rst_with_l2tp.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "6aa039f5c2be11ae72ec78346e50ab94"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}

/*
	L2TP ppp头部字段压缩隧道双向流注入包测试.
*/
void sapp_inject_l2tp_ppp_compress_double_dir_run(void)
{
	set_default_config();
  
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "MESA_rst_tcp_test_init_v4", "gtest_sapp_inject_plug_destory", "UDP", "inject_only_for_l2tp_tunnel_entry_c2s");

	update_config_file("etc/sapp.toml", "syn_mandatory", "1");
	update_config_file("etc/sapp.toml", "inject_pkt_mode", "raw_ethernet_single_gateway");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_device", "tap0");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_src_mac", "00:11:22:33:44:55");	
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_dst_mac", "00:11:22:33:44:66");

	set_default_asymmetric_addr_layer_conf("ethernet[*]\nvlan[*]\nmpls[*]\ngre[*]\ngtp[*]\n\n");

	set_pcap_dumpfile("for_gtest_only/inject/tcp_rst_with_l2tp_ppp_hdr_compress.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "62cbdf729199bcca78de9b4944da5256"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}


/* 4over6 SIO_DEFAULT 类型注入包测试 */
void sapp_inject_4over6_layer_run(void)
{
	set_default_config();
  
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "MESA_rst_tcp_test_init_v4", "gtest_sapp_inject_plug_destory", "TCP", "MESA_rst_tcp_plug_entry");

	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "inject_pkt_mode", "raw_ethernet_single_gateway");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_device", "tap0");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_src_mac", "00:11:22:33:44:55");	
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_dst_mac", "00:11:22:33:44:66");

	set_pcap_dumpfile("4over6/4over6.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "ffc01864863d5c400adcd4658f811d7b"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}

/* 4over6 SIO_EXCLUDE_THIS_LAYER_HDR 类型注入包测试 */
void sapp_inject_4over6_exclude_layer_run(void)
{
	set_default_config();
  
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "MESA_rst_tcp_test_init_v4", "gtest_sapp_inject_plug_destory", "TCP", "inject_raw_ipv4_exclude_tcp_entry");

	update_config_file("etc/sapp.toml", "syn_mandatory", "0");
	update_config_file("etc/sapp.toml", "inject_pkt_mode", "raw_ethernet_single_gateway");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_device", "tap0");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_src_mac", "00:11:22:33:44:55");	
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_dst_mac", "00:11:22:33:44:66");

	set_pcap_dumpfile("4over6/4over6.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "ffc01864863d5c400adcd4658f811d7b"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}


/* 6over4 SIO_DEFAULT 类型注入包测试 */
void sapp_inject_6over4_layer_run(void)
{
	set_default_config();
  
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "MESA_rst_tcp_test_init_v4", "gtest_sapp_inject_plug_destory", "TCP", "inject_raw_ipv6_pkt_tcp_entry");

	update_config_file("etc/sapp.toml", "syn_mandatory", "1");
	update_config_file("etc/sapp.toml", "inject_pkt_mode", "raw_ethernet_single_gateway");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_device", "tap0");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_src_mac", "00:11:22:33:44:55");	
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_dst_mac", "00:11:22:33:44:66");

	set_pcap_dumpfile("6over4/ipv6_over_ipv4.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "5b512b3321164a73446bdd54f7d20057"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}



/* 6over4 SIO_EXCLUDE_THIS_LAYER_HDR 类型注入包测试 */
void sapp_inject_6over4_exclude_layer_run(void)
{
	set_default_config();
  
	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf"); 

	update_plugin_inf_with_options("./plug/business/gtest_sapp", "gtest", "MESA_rst_tcp_test_init_v4", "gtest_sapp_inject_plug_destory", "TCP", "inject_raw_ipv6_exclude_tcp_entry");

	update_config_file("etc/sapp.toml", "syn_mandatory", "1");
	update_config_file("etc/sapp.toml", "inject_pkt_mode", "raw_ethernet_single_gateway");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_device", "tap0");
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_src_mac", "00:11:22:33:44:55");	
	update_config_file("etc/sapp.toml", "inject_mode_single_gateway_dst_mac", "00:11:22:33:44:66");

	set_pcap_dumpfile("6over4/ipv6_over_ipv4.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "5b512b3321164a73446bdd54f7d20057"),0);
	
	call_libsapp_devel_with_args(2, sapp_start_args);
}


