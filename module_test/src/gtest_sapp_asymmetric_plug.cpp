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
	非对称mpls自动对准, C2S方向没有mpls,但是S2C方向有MPLS, 不是靠创建空层解决.
*/
extern "C" char asymmetric_mpls_c2s_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	struct layer_addr_mpls *mplsaddr;
	
	if(OP_STATE_PENDING == pstream->opstate){
		/* 第一个包没有mpls, pending阶段的father是eth层 */
		if(pstream->pfather->addr.addrtype != ADDR_TYPE_MAC){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_c2s", "\033[1;31;40masymmetric_mpls_c2s_entry(): pending state, pfather->addr type is not ETH!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
			return APP_STATE_DROPME;
		}
		if(pstream->pfather->pfather != NULL){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_c2s","\033[1;31;40masymmetric_mpls_c2s_entry(): pending state, pfather->pfather is not NULL!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
			return APP_STATE_DROPME;
		}		
	}else if(OP_STATE_CLOSE == pstream->opstate){
		if(pstream->pfather->addr.addrtype != ADDR_TYPE_MPLS){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_c2s","\033[1;31;40masymmetric_mpls_c2s_entry(): close state, addr type is not MPLS!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}
		if(pstream->pfather->pfather->addr.addrtype != ADDR_TYPE_MAC){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_c2s","\033[1;31;40masymmetric_mpls_c2s_entry(): pending state, pfather->pfather addr type is not ETH!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
			return APP_STATE_DROPME;
		}
		
		if(pstream->pfather->pfather->pfather != NULL){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_c2s","\033[1;31;40masymmetric_mpls_c2s_entry(): close state, pfather->pfather->pfather is not NULL!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}	

		mplsaddr = pstream->pfather->addr.mpls;
		if(1 != mplsaddr->s2c_layer_num){ /* S2C方向的单侧有MPLS层 */
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_c2s","\033[1;31;40masymmetric_mpls_c2s_entry(): close state, S2C dir mpls layer num is not 1\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}		
		if(0 != mplsaddr->c2s_layer_num){ /* S2C方向的单侧有MPLS层 */
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_c2s","\033[1;31;40masymmetric_mpls_c2s_entry(): close state, C2S dir mpls layer num is not 0\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}				
		if(19 != ntohl(mplsaddr->s2c_addr_array[0].label)){ /* S2C方向的单侧有MPLS层 */
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_c2s","\033[1;31;40masymmetric_mpls_c2s_entry(): close state, S2C dir mpls label is not 19\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}
		if(6 != mplsaddr->s2c_addr_array[0].experimental){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_c2s","\033[1;31;40masymmetric_mpls_c2s_entry(): close state, S2C dir mpls experimental is not 6\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}

		if(pstream->ptcpdetail->serverpktnum != 1){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_c2s","\033[1;31;40masymmetric_mpls_c2s_entry(): close state, C2S pkt num is not 1\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}
		if(pstream->ptcpdetail->clientpktnum != 1){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_c2s","\033[1;31;40masymmetric_mpls_c2s_entry(): close state, S2C pkt num is not 1\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}
		if(pstream->ptcpdetail->serverbytes != 2129){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_c2s","\033[1;31;40masymmetric_mpls_c2s_entry(): close state, C2S pkt byte is not 2129\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}
		if(pstream->ptcpdetail->clientbytes != 693){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_c2s","\033[1;31;40masymmetric_mpls_c2s_entry(): close state, S2C pkt byte is not 693\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}

		SAPP_PLUG_LOG(RLOG_LV_INFO, "asymmetric_mpls_c2s", "\033[32masymmetric_mpls_c2s_entry() test succ!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_SUCC);
	}
	
	return APP_STATE_GIVEME;
}

extern "C" char asymmetric_mpls_s2c_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	struct layer_addr_mpls *mplsaddr;
	
	if(OP_STATE_PENDING == pstream->opstate){
		/* 与c2s_entry不同, 第一个包有mpls   */
		if(pstream->pfather->addr.addrtype != ADDR_TYPE_MPLS){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_s2c","\033[1;31;40m asymmetric_mpls_s2c_entry(): pending state, addr type is not MPLS!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
		}
		if(pstream->pfather->pfather->addr.addrtype != ADDR_TYPE_MAC){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_s2c","\033[1;31;40m asymmetric_mpls_s2c_entry(): pending state, pfather->pfather addr type is not ETH!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
			return APP_STATE_DROPME;
		}		
	}else if(OP_STATE_CLOSE == pstream->opstate){
		if(pstream->pfather->pfather->pfather != NULL){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_s2c","\033[1;31;40m asymmetric_mpls_s2c_entry(): close state, pfather->pfather->pfather is not NULL!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}	

		mplsaddr = pstream->pfather->addr.mpls;
		if(1 != mplsaddr->c2s_layer_num){  
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_s2c","\033[1;31;40masymmetric_mpls_s2c_entry(): close state, C2S dir mpls layer num is not 1\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}		
		if(0 != mplsaddr->s2c_layer_num){ 
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_s2c","\033[1;31;40masymmetric_mpls_s2c_entry(): close state, S2C dir mpls layer num is not 0\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}				
		if(656640 != ntohl(mplsaddr->c2s_addr_array[0].label)){ /* C2S方向的单侧有MPLS层 */
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_s2c","\033[1;31;40m asymmetric_mpls_s2c_entry(): close state, C2S dir mpls label is not 656640\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}
		if(6 != mplsaddr->c2s_addr_array[0].experimental){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_s2c","\033[1;31;40m asymmetric_mpls_s2c_entry(): close state, C2S dir mpls experimental is not 6\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}

		if(pstream->ptcpdetail->serverpktnum != 2){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_s2c","\033[1;31;40m asymmetric_mpls_s2c_entry(): close state, C2S pkt num is not 2\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}
		if(pstream->ptcpdetail->clientpktnum != 1){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_s2c","\033[1;31;40m asymmetric_mpls_s2c_entry(): close state, S2C pkt num is not 1\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}
		if(pstream->ptcpdetail->serverbytes != 2){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_s2c","\033[1;31;40m asymmetric_mpls_s2c_entry(): close state, C2S pkt byte is not 2\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}
		if(pstream->ptcpdetail->clientbytes != 2){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_s2c","\033[1;31;40m asymmetric_mpls_s2c_entry(): close state, S2C pkt byte is not 2\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}

		SAPP_PLUG_LOG(RLOG_LV_INFO, "asymmetric_mpls_s2c","\033[32m asymmetric_mpls_s2c_entry() test succ!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_SUCC);
	}
	
	return APP_STATE_GIVEME;
}


extern "C" char asymmetric_vlan_c2s_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	struct layer_addr_vlan *vladdr;
	
	if(OP_STATE_PENDING == pstream->opstate){
		if(pstream->pfather->addr.addrtype != ADDR_TYPE_VLAN){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_vlan_c2s","\033[1;31;40masymmetric_vlan_c2s_entry(): close state, addr type is not VLAN!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}
		if(pstream->pfather->pfather->addr.addrtype != ADDR_TYPE_MAC){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_vlan_c2s","\033[1;31;40masymmetric_vlan_c2s_entry(): pending state, pfather->pfather addr type is not ETH!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
			return APP_STATE_DROPME;
		}	
	}else if(OP_STATE_CLOSE == pstream->opstate){
		if(pstream->pfather->pfather->pfather != NULL){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_vlan_c2s","\033[1;31;40masymmetric_vlan_c2s_entry(): close state, pfather->pfather->pfather is not NULL!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}	

		vladdr = pstream->pfather->addr.vlan;
		if(30 != ntohs(vladdr->c2s_addr_array[0].VID)){ /* S2C方向的单侧有MPLS层 */
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_vlan_c2s","\033[1;31;40masymmetric_vlan_c2s_entry(): close state, C2S dir vlan VID is not 30\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}
		if(0x0800 != ntohs(vladdr->c2s_addr_array[0].TPID)){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_vlan_c2s","\033[1;31;40masymmetric_vlan_c2s_entry(): close state, C2S dir vlan TPID is not 0x0800\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}

		if(pstream->ptcpdetail->serverpktnum != 2){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_vlan_c2s","\033[1;31;40masymmetric_vlan_c2s_entry(): close state, C2S pkt num is not 2\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}
		if(pstream->ptcpdetail->clientpktnum != 1){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_vlan_c2s","\033[1;31;40masymmetric_vlan_c2s_entry(): close state, S2C pkt num is not 1\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}
		if(pstream->ptcpdetail->serverbytes != 1007){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_vlan_c2s","\033[1;31;40masymmetric_vlan_c2s_entry(): close state, C2S pkt byte is not 1007\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}
		if(pstream->ptcpdetail->clientbytes != 1460){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_vlan_c2s","\033[1;31;40masymmetric_vlan_c2s_entry(): close state, S2C pkt byte is not 1460\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}

		SAPP_PLUG_LOG(RLOG_LV_INFO, "asymmetric_vlan_c2s","\033[32masymmetric_vlan_c2s_entry() test succ!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_SUCC);
	}
	
	return APP_STATE_GIVEME;
}


extern "C" char asymmetric_vlan_s2c_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	struct layer_addr_vlan *vladdr;
	
	if(OP_STATE_PENDING == pstream->opstate){
		/* 第一个包没有vlan, pending阶段的father是eth层 */
		if(pstream->pfather->addr.addrtype != ADDR_TYPE_MAC){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_vlan_s2c","\033[1;31;40m asymmetric_vlan_s2c_entry(): pending state, pfather->addr type is not ETH!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
			return APP_STATE_DROPME;
		}
		if(pstream->pfather->pfather != NULL){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_vlan_s2c","\033[1;31;40m asymmetric_vlan_s2c_entry(): pending state, pfather->pfather is not NULL!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
			return APP_STATE_DROPME;
		}	

	}else if(OP_STATE_CLOSE == pstream->opstate){
		if(pstream->pfather->pfather->pfather != NULL){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_vlan_s2c","\033[1;31;40m asymmetric_vlan_s2c_entry(): close state, pfather->pfather->pfather is not NULL!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}	

		vladdr = pstream->pfather->addr.vlan;
		if(279 != ntohs(vladdr->c2s_addr_array[0].VID)){ /* C2S方向的单侧有vlan层 */
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_vlan_s2c","\033[1;31;40m asymmetric_vlan_s2c_entry(): close state, C2S dir vlan VID is not 279\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}
		if(0x0800 != ntohs(vladdr->c2s_addr_array[0].TPID)){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_vlan_s2c","\033[1;31;40m asymmetric_vlan_s2c_entry(): close state, C2S dir vlan TPID is not 0x0800\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}

		if(pstream->ptcpdetail->serverpktnum != 1){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_vlan_s2c","\033[1;31;40m asymmetric_vlan_s2c_entry(): close state, C2S pkt num is not 1\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}
		if(pstream->ptcpdetail->clientpktnum != 1){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_vlan_s2c","\033[1;31;40m asymmetric_vlan_s2c_entry(): close state, S2C pkt num is not 1\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}
		if(pstream->ptcpdetail->serverbytes != 1303){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_vlan_s2c","\033[1;31;40m asymmetric_vlan_s2c_entry(): close state, C2S pkt byte is not 1303\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}
		if(pstream->ptcpdetail->clientbytes != 1385){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_vlan_s2c","\033[1;31;40m asymmetric_vlan_s2c_entry(): close state, S2C pkt byte is not 1385\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}

		SAPP_PLUG_LOG(RLOG_LV_INFO, "asymmetric_vlan_s2c","\033[32m asymmetric_vlan_s2c_entry() test succ!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_SUCC);
	}
	
	return APP_STATE_GIVEME;
}


extern "C" char asymmetric_mpls_and_vlan_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	const struct layer_addr_mpls *outer_mpls_addr, *inner_mpls_addr;
	const struct layer_addr_vlan *inner_vlan_addr;
	
	if(OP_STATE_PENDING == pstream->opstate){
		if(NULL == pstream->pfather || NULL == pstream->pfather->pfather){
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
			return APP_STATE_DROPME;		
		}

		if(pstream->pfather->pfather->addr.addrtype != ADDR_TYPE_MPLS){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_and_vlan","\033[1;31;40m asymmetric_mpls_and_vlan_c2s_entry(): pending state, pfather->pfather->addr type is not MPLS!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
			return APP_STATE_DROPME;
		}
		outer_mpls_addr = pstream->pfather->pfather->addr.mpls;
		if(262434 != ntohl(outer_mpls_addr->c2s_addr_array[0].label)){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_and_vlan","\033[1;31;40m asymmetric_mpls_and_vlan_c2s_entry(): close state, C2S dir outer mpls label is not 262434\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}		
		if(5 != outer_mpls_addr->c2s_addr_array[0].experimental){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_and_vlan","\033[1;31;40m asymmetric_mpls_and_vlan_c2s_entry(): close state, C2S dir outer mpls experimental is not 5\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}
	}else if(OP_STATE_CLOSE == pstream->opstate){
		if(pstream->pfather->addr.addrtype != ADDR_TYPE_MPLS){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_and_vlan","\033[1;31;40m asymmetric_mpls_and_vlan_c2s_entry(): close state, pfather->addr type is not MPLS!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}
		if(pstream->pfather->pfather->addr.addrtype != ADDR_TYPE_VLAN){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_and_vlan","\033[1;31;40m asymmetric_mpls_and_vlan_c2s_entry(): pending state, pfather->pfather->addr type is not VLAN!\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR);	
			return APP_STATE_DROPME;
		}

		inner_mpls_addr = pstream->pfather->addr.mpls;
		if(2 != inner_mpls_addr->s2c_layer_num){ /* S2C方向的内层有2层MPLS */
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_and_vlan","\033[1;31;40m asymmetric_mpls_and_vlan_c2s_entry(): close state, S2C dir inner mpls layer num is not 1\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}		
		if(0 != inner_mpls_addr->c2s_layer_num){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_and_vlan","\033[1;31;40m asymmetric_mpls_and_vlan_c2s_entry(): close state, C2S dir inner mpls layer num is not 0\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}			

		/* 0是最外层, 3是最内层 */
		if(32915 != ntohl(inner_mpls_addr->s2c_addr_array[0].label)){  
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_and_vlan","\033[1;31;40m asymmetric_mpls_and_vlan_c2s_entry(): close state, S2C dir mpls label[0] is not 32915\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}
		if(32847 != ntohl(inner_mpls_addr->s2c_addr_array[1].label)){  
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_and_vlan","\033[1;31;40m asymmetric_mpls_and_vlan_c2s_entry(): close state, S2C dir mpls label[1] is not 32847\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}

		inner_vlan_addr = pstream->pfather->pfather->addr.vlan;
		if(inner_vlan_addr->s2c_layer_num !=2 ){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_and_vlan","\033[1;31;40m asymmetric_mpls_and_vlan_c2s_entry(): close state, S2C dir inner vlan layer num is not 2\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}
		if(inner_vlan_addr->c2s_layer_num != 0){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_and_vlan","\033[1;31;40m asymmetric_mpls_and_vlan_c2s_entry(): close state, C2S dir inner vlan layer num is not 0\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}		
		if(333 != ntohs(inner_vlan_addr->s2c_addr_array[0].VID)){ 
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_and_vlan","\033[1;31;40m asymmetric_mpls_and_vlan_c2s_entry(): close state, S2C dir inner vlan VID[0] is not 333\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}
		if(707 != ntohs(inner_vlan_addr->s2c_addr_array[1].VID)){ 
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_and_vlan","\033[1;31;40m asymmetric_mpls_and_vlan_c2s_entry(): close state, S2C dir inner vlan VID[1] is not 707\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}

		outer_mpls_addr = pstream->pfather->pfather->pfather->pfather->addr.mpls;
		/* 再判断一遍C2S方向的值 */
		if(262434 != ntohl(outer_mpls_addr->c2s_addr_array[0].label)){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_and_vlan","\033[1;31;40m asymmetric_mpls_and_vlan_c2s_entry(): close state, C2S dir outer mpls label is not 262434\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}	
		if(779408 != ntohl(outer_mpls_addr->s2c_addr_array[0].label)){  
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_and_vlan","\033[1;31;40m asymmetric_mpls_and_vlan_c2s_entry(): close state, S2C dir outer mpls label[0] is not 779408\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}
		if(262455 != ntohl(outer_mpls_addr->s2c_addr_array[1].label)){  
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_and_vlan","\033[1;31;40m asymmetric_mpls_and_vlan_c2s_entry(): close state, S2C dir outer mpls label[1] is not 262455\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}


		if(pstream->pudpdetail->serverpktnum != 1){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_and_vlan","\033[1;31;40m asymmetric_mpls_and_vlan_c2s_entry(): close state, C2S pkt num is not 1\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}
		if(pstream->ptcpdetail->clientpktnum != 1){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_and_vlan","\033[1;31;40m asymmetric_mpls_and_vlan_c2s_entry(): close state, S2C pkt num is not 1\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}
		if(pstream->ptcpdetail->serverbytes != 28){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_and_vlan","\033[1;31;40m asymmetric_mpls_and_vlan_c2s_entry(): close state, C2S pkt byte is not 28\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}
		if(pstream->ptcpdetail->clientbytes != 44){
			SAPP_PLUG_LOG(RLOG_LV_FATAL, "asymmetric_mpls_and_vlan","\033[1;31;40m asymmetric_mpls_and_vlan_c2s_entry(): close state, S2C pkt byte is not 44\033[0m\n");
			gtest_set_libsapp_devel_result(GTEST_SAPP_ERR); 
			return APP_STATE_DROPME;
		}

		SAPP_PLUG_LOG(RLOG_LV_INFO, "asymmetric_mpls_and_vlan","\033[32m asymmetric_mpls_and_vlan_c2s_entry() test succ!\033[0m\n");
		gtest_set_libsapp_devel_result(GTEST_SAPP_SUCC);
	}
	
	return APP_STATE_GIVEME;
}

