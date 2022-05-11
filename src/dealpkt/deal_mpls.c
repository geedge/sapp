
#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"

extern int ipv4_entry(struct streaminfo_private *pfstream, const void *this_layer_data, int thread_num, 
			unsigned char routedir, const raw_pkt_t *raw_pkt, int);

extern int ipv6_entry(struct streaminfo_private *pfstream, const void *this_layer_data, int thread_num,
                      unsigned char routedir, const raw_pkt_t *raw_pkt, int);

extern int eth_entry(struct streaminfo_private *fstream_pr, const void *this_layer_hdr,int thread_num,
					 unsigned char dir, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr);
extern int mpls_addr_net_to_mem(const struct mesa_mpls_hdr *net_mpls_hdr, struct single_layer_mpls_addr *mem_mpls_hdr);

static int guess_mpls_with_control_word(const unsigned char *maybe_eth_hdr)
{
	const struct mesa_ethernet_hdr *ehdr = (struct mesa_ethernet_hdr *)(maybe_eth_hdr);

	/* 
	    MPLS没有字段表示承载的协议类型, 靠猜!!
	    
	    https://tools.ietf.org/html/rfc4623
	    https://wiki.mikrotik.com/wiki/Manual:VPLS_Control_Word
	    https://www.ciscopress.com/articles/article.asp?p=386788&seqNum=2
	    
	    除标准的ipv4, ipv6之外, 还有可能是ethernet, 还有可能是带PW Ethernet Control Word的, 格式如下:
	    
        0               1               2                 3
		0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|0 0 0 0| flags |frag|len(6bit) |    Sequence Number(16bit)     |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		实际情况证明, 靠4bit是否==0为条件, 还是可能猜错, 再判断一下以太类型是否为常见类型.
	*/

	switch(ntohs(ehdr->ether_type)){
		case ETH_P_IP:
		case ETH_P_IPV6:
		case ETH_P_8021Q:
		case ETH_P_MPLS_UC:
		case ETH_P_PPP_SES:
			return 0; /* 合法的ethernet类型, 不含CW */
		break;

		default:
		break;
	}

	ehdr = (struct mesa_ethernet_hdr *)(maybe_eth_hdr + 4);
	switch(ntohs(ehdr->ether_type)){
		case ETH_P_IP:
		case ETH_P_IPV6:
		case ETH_P_8021Q:
		case ETH_P_MPLS_UC:
		case ETH_P_PPP_SES:
			return 1; /* 合法的ethernet类型, 包含CW */
		break;
		
		default:
		break;		
	}

	/* TODO: 以上都不是, 此处应该返回个什么值? */
	return 0;
}

int set_mpls_addr(struct layer_addr_mpls *addr, const unsigned char *raw_mpls_pkt_data)
{
	assert(raw_mpls_pkt_data != NULL);
	const struct mesa_mpls_hdr *this_mpls_hdr = NULL;
	int i;

	memset(addr, 0, sizeof(struct layer_addr_mpls));
	for (i = 0; i < MAX_MPLS_ADDR_LAYER; i++)
	{
		this_mpls_hdr = (const struct mesa_mpls_hdr *)raw_mpls_pkt_data;
		// memcpy(&addr->src_mpls_pkt[i], raw_mpls_pkt_data,  sizeof(struct mesa_mpls_hdr));
		mpls_addr_net_to_mem(this_mpls_hdr, &addr->c2s_addr_array[i]); /* 函数栈里的地址, 每次暂存在c2s方向, TCP/UDP层再根据流方向翻转 */

		addr->c2s_layer_num += 1;
		if (1 == this_mpls_hdr->mpls_bls)
		{
			raw_mpls_pkt_data += sizeof(struct mesa_mpls_hdr); /* 为了后面方便判断是否还有ctrl word */
			break;
		}
		raw_mpls_pkt_data += sizeof(struct mesa_mpls_hdr);
	}

	assert(this_mpls_hdr != NULL);
	if (1 != this_mpls_hdr->mpls_bls) /* 超过MAX_MPLS_ADDR_LAYER, MPLS还没有结束 */
	{
		sapp_runtime_log(RLOG_LV_FATAL, "MPLS layer number over load, only support %d\n", MAX_MPLS_ADDR_LAYER);
		return -1;
	}

	if (((*raw_mpls_pkt_data & 0xF0) != 0x40) && ((*raw_mpls_pkt_data & 0xF0) != 0x60))
	{ // VPLS, MPLS with Control Word
		if (guess_mpls_with_control_word(raw_mpls_pkt_data) > 0)
		{
			memcpy(&addr->c2s_mpls_ctrl_word, raw_mpls_pkt_data, sizeof(int));
			addr->c2s_has_ctrl_word = 1;
		}
	}

	return 0;
}

int mpls_uc_entry(struct streaminfo_private *pfstream_pr,const void *this_layer_data,int thread_num, 
						unsigned char routedir, const raw_pkt_t *raw_pkt,int offset_to_raw_pkt_hdr)
{
	int ret = PASS;
	struct streamindex tmp_index;
	struct layer_addr_mpls addr;
	struct streamindex *ptmp = &tmp_index;
	struct streaminfo_private *pstream_pr = &ptmp->stream;
	struct streaminfo *pstream = &pstream_pr->stream_public;
	char *next_layer_hdr = NULL;
	int next_layer_offset = 0, i = 0;
	int inject_to_eth_flag = 0;
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[thread_num]->sys_stat;

	local_sys_stat->count_per_layer[ADDR_TYPE_MPLS][pfstream_pr->layer_index + 1]++;
	local_sys_stat->length_per_layer[ADDR_TYPE_MPLS][pfstream_pr->layer_index + 1] += raw_pkt->raw_pkt_len - offset_to_raw_pkt_hdr;

	if (set_mpls_addr(&addr, (unsigned char *)this_layer_data) < 0)
	{
		local_sys_stat->count[SAPP_STAT_RCV_UNKNOWN]++;
		local_sys_stat->length[SAPP_STAT_RCV_UNKNOWN] += raw_pkt->raw_pkt_len;
		((raw_pkt_t *)raw_pkt)->diagnose_error_to_dump = 1;
		return PASS;
	}

	next_layer_offset = offset_to_raw_pkt_hdr + sizeof(struct mesa_mpls_hdr) * addr.c2s_layer_num;
	next_layer_hdr = (char *)this_layer_data + sizeof(struct mesa_mpls_hdr) * addr.c2s_layer_num;

	if (0 == G_SKIP_NOT_IP_LAYER)
	{
		memset(ptmp, 0, sizeof(struct streamindex));
		pstream->addr.paddr = &addr;
		pstream->addr.addrtype = ADDR_TYPE_MPLS;
		pstream->addr.addrlen = sizeof(struct layer_addr_mpls);
		pstream_pr->offset_to_raw_pkt_hdr = offset_to_raw_pkt_hdr;
		pstream_pr->raw_pkt = raw_pkt;

		pstream->pfather = &pfstream_pr->stream_public;
		pstream_pr->pfather_pr = pfstream_pr;
		pstream->type = STREAM_TYPE_NON;
		pstream->routedir = routedir;
		pstream->threadnum = thread_num;

		pstream_pr->layer_index = pfstream_pr->layer_index + 1;
		if (g_asymmetric_addr_layer_set.layer_type_index[ADDR_TYPE_MPLS][pstream_pr->layer_index] != 0)
		{
			pstream_pr->need_update_opposite_addr = 1; //两侧地址不一样，需要更新对侧信息
		}
		else
		{
			pstream_pr->need_update_opposite_addr = 0;
		}

		pstream_pr->addr_use_as_hash = g_stream_compare_layer_set.layer_type_index[ADDR_TYPE_MPLS][pstream_pr->layer_index];
	}
	else
	{
		pstream_pr = pfstream_pr;
	}

	((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offset;
	unsigned char guess_ip_version = (*next_layer_hdr & 0xF0) >> 4;
	if (4 == guess_ip_version)
	{
		/* 直接注入ipv4_entry(), 如果猜错了也没什么问题, checkipv4pkt()也能检查出来,
		   但是万一是mac地址以0x4x开头, 就没机会再注入ethernet层再处理一遍了, 可能丢失某些数据,
		   所以, 此处提前检查一些错误！
		*/
		struct mesa_ip4_hdr *ip4_hdr = (struct mesa_ip4_hdr *)next_layer_hdr;

		if (ip4_hdr->ip_p >= 0x8F)
		{ /* IP协议字段大于0x8f的目前不合法 */
			inject_to_eth_flag = 1;
		}

		int left_pkt_len = raw_pkt->raw_pkt_len - next_layer_offset;
		if (left_pkt_len < ntohs(ip4_hdr->ip_len))
		{
			local_sys_stat->count[SAPP_STAT_RCV_UNKNOWN]++;
			local_sys_stat->length[SAPP_STAT_RCV_UNKNOWN] += raw_pkt->raw_pkt_len;
			((raw_pkt_t *)raw_pkt)->diagnose_error_to_dump = 1;
			sapp_runtime_log(20, "illegal left Ipv4 len %d, total len %d!\n", left_pkt_len, ntohs(ip4_hdr->ip_len));
			inject_to_eth_flag = 1;
		}

		if (0 == inject_to_eth_flag)
		{
			ret = ipv4_entry(pstream_pr, next_layer_hdr, thread_num, routedir, raw_pkt, next_layer_offset);
		}
	}
	else if (6 == guess_ip_version)
	{
		/* 直接注入ipv6_entry(), 如果猜错了也没什么问题, checkipv6pkt()也能检查出来,
		   但是万一是mac地址以0x6x开头, 就没机会再注入ethernet层再处理一遍了, 可能丢失某些数据,
		   所以, 此处提前检查一些错误！
		*/
		struct mesa_ip6_hdr *ip6_hdr = (struct mesa_ip6_hdr *)next_layer_hdr;
		if (ip6_hdr->ip6_nxt_hdr >= 0x8F)
		{ /* IP协议字段大于0x8f的目前不合法 */
			inject_to_eth_flag = 1;
		}

		int left_pkt_len = raw_pkt->raw_pkt_len - next_layer_offset;
		if (left_pkt_len < sizeof(struct mesa_ip6_hdr) + ntohs(ip6_hdr->ip6_payload_len))
		{
			local_sys_stat->count[SAPP_STAT_RCV_UNKNOWN]++;
			local_sys_stat->length[SAPP_STAT_RCV_UNKNOWN] += raw_pkt->raw_pkt_len;
			((raw_pkt_t *)raw_pkt)->diagnose_error_to_dump = 1;
			sapp_runtime_log(20, "illegal left Ipv6 len %d, total len %d!\n", left_pkt_len, ntohs(ip6_hdr->ip6_payload_len));
			inject_to_eth_flag = 1;
		}

		if (0 == inject_to_eth_flag)
		{
			ret = ipv6_entry(pstream_pr, next_layer_hdr, thread_num, routedir, raw_pkt, next_layer_offset);
		}
	}
	else
	{
		inject_to_eth_flag = 1;
	}

	if (inject_to_eth_flag != 0)
	{
		if (addr.c2s_has_ctrl_word != 0)
		{
			ret = eth_entry(pstream_pr, next_layer_hdr + 4, thread_num, routedir, raw_pkt, next_layer_offset + 4);
		}
		else
		{
			int left_pkt_len = raw_pkt->raw_pkt_len - next_layer_offset;
			if (left_pkt_len < sizeof(struct mesa_ethernet_hdr) + sizeof(struct mesa_ip4_hdr) + sizeof(struct mesa_udp_hdr))
			{ /* 小于最小合法ethernet+ip+udp数据包长度 */
				local_sys_stat->count[SAPP_STAT_RCV_UNKNOWN]++;
				local_sys_stat->length[SAPP_STAT_RCV_UNKNOWN] += raw_pkt->raw_pkt_len;
				((raw_pkt_t *)raw_pkt)->diagnose_error_to_dump = 1;

				sapp_runtime_log(20, "MPLS next layer type: 0x%x, but left len only:%d, pkt seq:%llu\n", *next_layer_hdr, left_pkt_len, local_sys_stat->count[SAPP_STAT_RCV_LINE]);
				return PASS;
			}

			ret = eth_entry(pstream_pr, next_layer_hdr, thread_num, routedir, raw_pkt, next_layer_offset);
		}
	}

	return ret;
}

/* 2021-05-06 lijia close, 非对称mpls改成动态插入streaminfo的方式解决.
   详见函数: streaminfo_layer_alignment()
*/ 	

#ifdef __cplusplus
}
#endif


