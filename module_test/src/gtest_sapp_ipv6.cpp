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

void ipv6_frag_assemble_simple_run(void)
{
	set_default_config();
	update_plugin_inf("IPV6", "ipv6_frag_assemble_simple");

	set_pcap_dumpfile("ipv6/ipv6_frag_simple.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "fddf170de4332ba3c0679c19d534dc9b"),0);
	
	call_libsapp_devel_for_dumpfile_topspeed();
}

void ipv6_frag_assemble_oos_run(void)
{
	set_default_config();
	update_plugin_inf("IPV6", "ipv6_frag_assemble_simple"); /* 使用同一个业务插件 */

	set_pcap_dumpfile("ipv6/ipv6_frag_oos.pcap");
	ASSERT_EQ(file_md5_checksum("dumpfile", "644b4f34a3f9f33754caa91a71e27058"),0);
		 
	call_libsapp_devel_for_dumpfile_topspeed();
}


void ipv6_frag_udp_assemble_run(void)
{
  set_default_config();
  append_project_list_conf("ipv6_frag_list",  "struct");
  update_plugin_inf("UDP", "ipv6_frag_assemble_udp_entry");

  set_pcap_dumpfile("for_gtest_only/udp/udp_ipv6_frag.pcap");
  ASSERT_EQ(file_md5_checksum("dumpfile", "c55092cd8cd165a54c0671743b155fc0"),0);
  
  call_libsapp_devel_for_dumpfile_topspeed();
}


