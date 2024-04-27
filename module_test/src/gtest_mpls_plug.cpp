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


extern "C" char tcp_entry_for_asymmetric_1vs2(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	const struct streaminfo *mpls_pstream = pstream->pfather;
	
	if(OP_STATE_CLOSE == pstream->opstate){
		if(mpls_pstream->addr.addrtype != ADDR_TYPE_MPLS){
			printf("\033[1;31;40mnot found mpls stream layer!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}

		/* c2s */
		if(mpls_pstream->addr.mpls->c2s_layer_num != 2){
			printf("\033[1;31;40mmpls c2s layer num error, expect 2, but actual is:%d!\033[0m\n", mpls_pstream->addr.mpls->c2s_layer_num);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
			return APP_STATE_DROPME;
		}
		
		if(ntohl(mpls_pstream->addr.mpls->c2s_addr_array[0].label) != 301632){
			printf("\033[1;31;40mmpls c2s addr error, expect label:301632, but actual is:%u!\033[0m\n", ntohl(mpls_pstream->addr.mpls->c2s_addr_array[0].label));
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
			return APP_STATE_DROPME;
		}

		if(mpls_pstream->addr.mpls->c2s_addr_array[0].experimental != 0){
			printf("\033[1;31;40mmpls c2s addr error, expect experimental:0, but actual is:%u!\033[0m\n", mpls_pstream->addr.mpls->c2s_addr_array[0].experimental);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
			return APP_STATE_DROPME;
		}
		

		if(mpls_pstream->addr.mpls->c2s_addr_array[0].ttl != 63){
			printf("\033[1;31;40mmpls c2s addr error, expect ttl:63, but actual is:%u!\033[0m\n", mpls_pstream->addr.mpls->c2s_addr_array[0].ttl);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
			return APP_STATE_DROPME;
		}

		if(ntohl(mpls_pstream->addr.mpls->c2s_addr_array[1].label) != 794436){
			printf("\033[1;31;40mmpls c2s addr error, expect label:794436, but actual is:%u!\033[0m\n", ntohl(mpls_pstream->addr.mpls->c2s_addr_array[1].label));
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
			return APP_STATE_DROPME;
		}

		if(mpls_pstream->addr.mpls->c2s_addr_array[1].experimental != 0){
			printf("\033[1;31;40mmpls c2s addr error, expect experimental:0, but actual is:%u!\033[0m\n", mpls_pstream->addr.mpls->c2s_addr_array[1].experimental);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
			return APP_STATE_DROPME;
		}
		

		if(mpls_pstream->addr.mpls->c2s_addr_array[1].ttl != 63){
			printf("\033[1;31;40mmpls c2s addr error, expect ttl:63, but actual is:%u!\033[0m\n", mpls_pstream->addr.mpls->c2s_addr_array[1].ttl);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
			return APP_STATE_DROPME;
		}

		if(mpls_pstream->addr.mpls->c2s_addr_array[1].bottom != 1){
			printf("\033[1;31;40mmpls c2s addr error, expect bottom:1, but actual is:%u!\033[0m\n", mpls_pstream->addr.mpls->c2s_addr_array[1].bottom);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
			return APP_STATE_DROPME;
		}

		/* s2c */
		if(mpls_pstream->addr.mpls->s2c_layer_num != 1){
			printf("\033[1;31;40mmpls s2c layer num error, expect 1, but actual is:%d!\033[0m\n", mpls_pstream->addr.mpls->s2c_layer_num);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
			return APP_STATE_DROPME;
		}
		
		if(ntohl(mpls_pstream->addr.mpls->s2c_addr_array[0].label) != 23041){
			printf("\033[1;31;40mmpls c2s addr error, expect label:23041, but actual is:%u!\033[0m\n", ntohl(mpls_pstream->addr.mpls->s2c_addr_array[0].label));
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
			return APP_STATE_DROPME;
		}

		if(mpls_pstream->addr.mpls->s2c_addr_array[0].experimental != 6){
			printf("\033[1;31;40mmpls c2s addr error, expect experimental:6, but actual is:%u!\033[0m\n", mpls_pstream->addr.mpls->s2c_addr_array[0].experimental);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
			return APP_STATE_DROPME;
		}

		if(mpls_pstream->addr.mpls->s2c_addr_array[0].ttl != 251){
			printf("\033[1;31;40mmpls c2s addr error, expect ttl:251, but actual is:%u!\033[0m\n", mpls_pstream->addr.mpls->s2c_addr_array[0].ttl);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
			return APP_STATE_DROPME;
		}

		if(mpls_pstream->addr.mpls->s2c_addr_array[0].bottom != 1){
			printf("\033[1;31;40mmpls c2s addr error, expect bottom:1, but actual is:%u!\033[0m\n", mpls_pstream->addr.mpls->s2c_addr_array[0].bottom);
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
			return APP_STATE_DROPME;
		}

		printf("\033[32mtest mpls 1vs2 success!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_SUCC);
	}

	return APP_STATE_GIVEME;
}

