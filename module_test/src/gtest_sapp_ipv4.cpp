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
void ipv4_frag_assemble_simple_run(void)
{
  set_default_config();
  
  update_plugin_inf("IP", "ipv4_frag_assemble_simple");

  set_pcap_dumpfile("ipv4/ipv4_frag_simple.pcap");

  ASSERT_EQ(file_md5_checksum("dumpfile", "80945cdfe7b14d78b2d84331a0e6e216"),0);
   
  call_libsapp_devel_for_dumpfile_topspeed();
}

void ipv4_frag_assemble_oos_run(void)
{
	set_default_config();
	
	update_plugin_inf("IP", "ipv4_frag_assemble_simple"); /* 使用同一个业务插件 */

	set_pcap_dumpfile("ipv4/ipv4_frag_out_of_order.pcap");

	ASSERT_EQ(file_md5_checksum("dumpfile", "b748061b54b26b802313af6df4129e6d"),0);

	call_libsapp_devel_for_dumpfile_topspeed();
}


void ipv4_frag_udp_assemble_run(void)
{
  set_default_config();

  append_project_list_conf("ipv4_frag_list",  "struct");
  
  update_plugin_inf("UDP", "ipv4_frag_assemble_udp_entry");

  set_pcap_dumpfile("for_gtest_only/udp/udp_ipv4_frag.pcap");

  ASSERT_EQ(file_md5_checksum("dumpfile", "6a81cf035ad2572173ed3b3a5b9fa540"),0);
  
  call_libsapp_devel_for_dumpfile_topspeed();
}

void ipv4_frag_assemble_checksum_run(void)
{
  set_default_config();
  
  update_plugin_inf("IP", "ipv4_frag_assemble_checksum");

  set_pcap_dumpfile("ipv4/ipv4_frag_simple.pcap");

  ASSERT_EQ(file_md5_checksum("dumpfile", "80945cdfe7b14d78b2d84331a0e6e216"),0);
  
  call_libsapp_devel_for_dumpfile_topspeed();
}


