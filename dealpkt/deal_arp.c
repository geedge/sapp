#ifdef __cplusplus
extern "C" {
#endif

#include "stream_internal.h"
#include "stream_manage.h"
#include "g_device.h"
#include "packet_io_internal.h"

extern int g_topology_mode;

 int arp_entry(struct streaminfo_private *pfstream_pr, const void *this_layer_hdr, 
 		int thread_num, unsigned char dir, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr)
{
	if(gdev_keepalive(raw_pkt, thread_num, GDEV_KEEPALIVE_TYPE_ARP, dir) > 0){
		return DROP;
	}

	/* 双网卡串联透明模式要转发ARP, 否则网络通讯无法正常获取对方MAC */
	if(NET_CONN_SERIAL_2CARD == g_topology_mode){
		return PASS;
	}
	/* NOTE: 其他模式什么时候都不应该把收到的原始ARP包再转发出去 */
	return DROP;
}

#ifdef __cplusplus
}
#endif

