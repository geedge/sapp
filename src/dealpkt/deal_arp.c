#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"

 int arp_entry(struct streaminfo_private *pfstream_pr, const void *this_layer_hdr, 
 		int thread_num, unsigned char dir, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr)
{
	/* 双网卡串联模式无条件转发ARP, 否则网络通讯无法正常获取对方MAC */
	if(NET_CONN_SERIAL_2CARD == g_topology_mode){
		return PASS;
	}
	
#if (0 == IOMODE_MARSIO) /* marsio模式下, 驱动负责回复ARP包, sapp不处理 */
	if(gdev_keepalive(raw_pkt, thread_num, GDEV_KEEPALIVE_TYPE_ARP, dir) > 0){
		return DROP;
	}
#endif

	/* NOTE: 其他模式什么时候都不应该把原始ARP包再转发出去, 即便是GDEV模式下 */
	return DROP;
}

#ifdef __cplusplus
}
#endif

