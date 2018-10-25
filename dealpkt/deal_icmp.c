#ifdef __cplusplus
extern "C" {
#endif

#include "stream_internal.h" 
#include "stream_manage.h"
#include "g_device.h"

int icmp_entry(struct streaminfo_private *pfstream_pr, const void *this_layer_hdr, 
	int thread_num, unsigned char dir, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr)							 
{
#if 0 /* 2017-05-19 lijia modify, GDEV保活转到g_device_plug插件中实现, 平台内部不再处理 */
	if(gdev_keepalive(raw_pkt, thread_num, GDEV_KEEPALIVE_TYPE_ICMP, dir) > 0){
		return DROP;
	}
#endif

	return PASS;
}

#ifdef __cplusplus
}
#endif

