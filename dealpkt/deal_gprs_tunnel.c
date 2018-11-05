#ifdef __cplusplus
extern "C" {
#endif

#include "stream_internal.h" 
#include "stream_manage.h"
#include "mesa_net.h"
#include "sysinfo.h"



int gtp_entry(struct streaminfo_private *pfstream_pr,void *this_layer_data,int thread_num, 
		unsigned char routedir, const raw_pkt_t *raw_packet, int offset_to_raw_pkt_hdr)
{

	/* TODO,
		创建gtp层结构, 分别记录C2S, S2C方向的地址, 
	*/

	
}


/*
	内置插件, 
	用于识别当前UDP流是否是隧道.
	如果是隧道, 在streaminfo_private->stream_carry_up_layer_tunnel_type中设置标记.
*/
char udp_gtp_identify_entry(const struct streaminfo *pstream, const void *this_hdr, const void *raw_pkt, void **pme)
{
	
	return APP_STATE_DROPME; /* 每个流只看第一个包, 不管是否GTP隧道, 后续都不再处理了 */
}


#ifdef __cplusplus
}
#endif


