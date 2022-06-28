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


extern "C" char tcp_entry_for_vlan_2layer(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	const struct streaminfo *vlan_pstream = pstream->pfather;
	
	if(OP_STATE_CLOSE == pstream->opstate){
		if(vlan_pstream->addr.addrtype != ADDR_TYPE_VLAN){
			printf("\033[1;31;40mnot found vlan stream layer!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}

		if(vlan_pstream->addr.vlan->c2s_layer_num != 0){
			printf("\033[1;31;40mvlan c2s_layer num is not 0!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}

		if(vlan_pstream->addr.vlan->s2c_layer_num != 2){
			printf("\033[1;31;40mvlan s2c layer num is not 2!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}
		

		if(ntohs(vlan_pstream->addr.vlan->s2c_addr_array[0].VID) != 118){
			printf("\033[1;31;40mvlan layer0 VID is not 118!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}
		if(vlan_pstream->addr.vlan->s2c_addr_array[0].PCP != 1){
			printf("\033[1;31;40mvlan layer0 PCP is not 1!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}		
		if(vlan_pstream->addr.vlan->s2c_addr_array[0].DEI != 1){
			printf("\033[1;31;40mvlan layer0 DEI is not 1!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}


		if(ntohs(vlan_pstream->addr.vlan->s2c_addr_array[1].VID) != 10){
			printf("\033[1;31;40mvlan layer1 VID is not 10!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}		
		if(vlan_pstream->addr.vlan->s2c_addr_array[1].PCP != 4){
			printf("\033[1;31;40mvlan layer0 PCP is not 4!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}		
		if(vlan_pstream->addr.vlan->s2c_addr_array[1].DEI != 0){
			printf("\033[1;31;40mvlan layer0 DEI is not 0!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}	


		printf("\033[32mtest vlan 2layer success!\033[0m\n");
		sendto_test_result(GTEST_SAPP_SUCC);		
	}

	return APP_STATE_GIVEME;
}

extern "C" char tcp_entry_for_vlan_asymmetric(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	const struct streaminfo *vlan_pstream = pstream->pfather;
	
	if(OP_STATE_CLOSE == pstream->opstate){
		if(vlan_pstream->addr.addrtype != ADDR_TYPE_MAC){
			printf("\033[1;31;40masymmetric should be skip vlan layer!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}

		if(pstream->ptcpdetail->serverpktnum != 18){
			printf("\033[1;31;40masymmetric vlan c2s tcp pkt is:%u, but expect:%d!\033[0m\n", pstream->ptcpdetail->serverpktnum, 18);
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}
		if(pstream->ptcpdetail->serverbytes != 4672){
			printf("\033[1;31;40masymmetric vlan c2s tcp byte is:%u, but expect:%d!\033[0m\n", pstream->ptcpdetail->serverbytes, 4672);
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}		
		if(pstream->ptcpdetail->clientpktnum != 27){
			printf("\033[1;31;40masymmetric vlan s2c tcp pkt is:%u, but expect:%d!\033[0m\n", pstream->ptcpdetail->clientpktnum, 27);
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}
		if(pstream->ptcpdetail->clientbytes != 53920){
			printf("\033[1;31;40masymmetric vlan s2c tcp byte is:%u, but expect:%d!\033[0m\n", pstream->ptcpdetail->clientbytes, 53920);
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;
		}

		printf("\033[32mtest vlan_asymmetric success!\033[0m\n");
		sendto_test_result(GTEST_SAPP_SUCC);		
	}

	return APP_STATE_GIVEME;
}


