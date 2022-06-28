#ifndef __USE_BSD
#define __USE_BSD
#endif
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/types.h>			/* See NOTES */
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/limits.h>
#include <linux/if_ether.h>
#include <pthread.h>

#include "stream.h"
#include "gtest_sapp_fun.h"
#include "stream_rawpkt.h"


/*
	底层是非对称mpls, 上层要识别为双向tcp流.
*/
extern "C" char fake_marsio_vlan_flipp_and_symmetric_mpls_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	if(pstream->opstate == OP_STATE_CLOSE){
		if(pstream->dir != DIR_DOUBLE){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "fake_marsio_vlan_flipp_and_symmetric_mpls","\033[1;31;40mfake_marsio_vlan_flipp_and_symmetric_mpls_entry: stream dir is not double!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;		
		}

		if((pstream->ptcpdetail->serverpktnum != 2)
		|| (pstream->ptcpdetail->serverbytes != 2)
		|| (pstream->ptcpdetail->clientpktnum != 1)
		|| (pstream->ptcpdetail->clientbytes != 2)){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "fake_marsio_vlan_flipp_and_symmetric_mpls","\033[1;31;40mfake_marsio_vlan_flipp_and_symmetric_mpls_entry: tcp stat error!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		}

		/*
			fake marsio插件错误结果立刻返回, 但是不返回正确结果, 
			在 fake_marsio_md5_tuple[] 里检查完后才能确定最终结果.
		*/
	}

	return APP_STATE_GIVEME;
}


extern "C" int fake_marsio_inject_tcp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	if(sapp_inject_pkt(pstream, SIO_DEFAULT, GINJECT_TEST_PAYLOAD, strlen(GINJECT_TEST_PAYLOAD), pstream->routedir) < 0){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "fake_marsio_inject","\033[1;31;40mfake_marsio_inject_tcp_entry() error!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	//printf("plug inject reverse pkt: routedir:%d\n", MESA_dir_reverse(pstream->routedir));
	if(sapp_inject_pkt(pstream, SIO_DEFAULT, GINJECT_TEST_PAYLOAD, strlen(GINJECT_TEST_PAYLOAD), MESA_dir_reverse(pstream->routedir)) < 0){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "fake_marsio_inject","\033[1;31;40mfake_marsio_inject_tcp_entry() rverse inject dir:%d error!\033[0m\n", MESA_dir_reverse(pstream->routedir));
		gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}	

	return APP_STATE_GIVEME | APP_STATE_DROPPKT;
}


