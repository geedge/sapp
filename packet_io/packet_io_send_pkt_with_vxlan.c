#include "packet_io.h"
#include "packet_io_internal.h"
#include "stream_manage.h"
#include "stream_internal.h"
#include "mesa_net.h"
#include "sendpacket.h"
#include <MESA_handle_logger.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>


#ifdef __cplusplus
extern "C" {
#endif


#define SMAC_ROUTE_DIR_MASK	(0x1)		/* 链路方向位 */
#define SMAC_LINK_ID_MASK		(0xE)		/* 链路ID */
#define SMAC_DEV_SEQ_MASK	(0x3F0)		/* 设备编号 */
#define SMAC_REGION_SEQ_MASK	(0x7C00)		/* 局点编号 */
#define SMAC_ENCAP_TYPE_MASK	(0xF0000)	/* 原始二层封装 */

#define SMAC_EXTRACT_ROUTE_DIR(n)  ((unsigned char)(n & SMAC_ROUTE_DIR_MASK))
#define SMAC_EXTRACT_LINK_ID(n)  	((unsigned char)((n & SMAC_LINK_ID_MASK) >> 1))
#define SMAC_EXTRACT_DEV_SEQ(n)  	((unsigned char)((n & SMAC_DEV_SEQ_MASK) >> 4))
#define SMAC_EXTRACT_REGION_SEQ(n)  ((unsigned char)((n & SMAC_REGION_SEQ_MASK) >> 10))
#define SMAC_EXTRACT_ENCAP_TYPE(n)  ((unsigned char)((n & SMAC_ENCAP_TYPE_MASK) >>16))


extern UINT64 MESA_rand_range(UINT64 start, UINT64 end);

/* 8字节大小端转换 */
static inline void sapp_ntoh_8byte(char *out, const char *in)
{
	out[0]	= in[7];
	out[1]	= in[6];
	out[2]	= in[5];
	out[3]	= in[4];
	out[4]	= in[3];
	out[5]	= in[2];
	out[6]	= in[1];
	out[7]	= in[0];
}

void packet_extract_para_from_mac_addr(const struct layer_addr_mac_in_mac *mimac,  struct pangu_mac_in_mac_mem_hdr *mim_mem_hdr)
{
	unsigned long long tmp_num_net = 0;
	unsigned long long tmp_num_host = 0;

	memcpy(&tmp_num_net, mimac->outer_src_mac, MAC_ADDR_LEN);
	tmp_num_net &= 0xFFFFFFFFFFFFUL; /* 清空最高两个字节 */

	sapp_ntoh_8byte((char *)&tmp_num_host, (char *)&tmp_num_net);

	mim_mem_hdr->route_dir = SMAC_EXTRACT_ROUTE_DIR(tmp_num_host);
	mim_mem_hdr->link_id = SMAC_EXTRACT_LINK_ID(tmp_num_host);
	mim_mem_hdr->dev_seq = SMAC_EXTRACT_DEV_SEQ(tmp_num_host);
	mim_mem_hdr->region_seq = SMAC_EXTRACT_REGION_SEQ(tmp_num_host);
	mim_mem_hdr->encap_type = SMAC_EXTRACT_ENCAP_TYPE(tmp_num_host);
}



#ifdef __cplusplus
}
#endif

