#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"
#include "sapp_declaration.h"

/*
	参考资料:
		https://en.wikipedia.org/wiki/GPRS_Tunnelling_Protocol
		https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=1595
		
*/

#define GPRS_TUNNEL_PORT (2152)


MESA_htable_handle g_gtp_info_hash[MAX_THREAD_NUM];

extern int ipv4_entry(struct streaminfo_private *pfstream, const void *this_layer_data, int thread_num,
                      unsigned char routedir, const raw_pkt_t *raw_pkt, int);

extern int ipv6_entry(struct streaminfo_private *pfstream, const void *this_layer_data, int thread_num,
                      unsigned char routedir, const raw_pkt_t *raw_pkt, int);

/*
  gprs头部根据标志位的不同, 长度也不同, 不能直接用sizeof(struct gtp_hdr)获取长度.
*/
int deal_gtp_calc_gtp_hdr_len(const struct gtp_hdr *gtph)
{
	const unsigned char *p_ext_hdr = (unsigned char *)gtph + sizeof(struct gtp_hdr);
	unsigned char next_hdr_type;
	unsigned char this_ext_field_cont_len;

	/* 
	   v0太古老了, 已被废弃;
	   不存在GTPv2-U协议, 在LTE中的GTP-U仍使用GTPv1-U, 
	   所以, sapp目前仅支持gtp v1版本.
	 */
	if(((gtph->flags & GTP_HDR_VER_MASK) >> 5) != 1){
	  return -1; 
	}

	if(gtph->flags & (GTP_HDR_FLAG_SEQ_NUM | GTP_HDR_FLAG_N_PDU | GTP_HDR_FLAG_NEXT_EXT_HDR)){
	  //todo, parse and get seq field
	  p_ext_hdr += 2; //seq field length is 2 bytes

	  //todo, parse and get N-PDU field
	  p_ext_hdr++; //N-PDU field length is 1 byte 

    /*
		解析gtp扩展头部字段, 
		参考3GPP文档第5.1, 5.2章节,
		以及wireshark源码, packet-gtp.c -> dissect_gtp_common()函数.
    */

	next_hdr_type = *p_ext_hdr;
	  if(gtph->flags & GTP_HDR_FLAG_NEXT_EXT_HDR){
		  while(next_hdr_type != 0){
		  	//todo, parse and get extension headers
			  p_ext_hdr++; //指向长度字段, 以4个字节为单位
			  this_ext_field_cont_len = *p_ext_hdr * 4 - 2;

			  p_ext_hdr++; //指向数据部分第一个字节
			  p_ext_hdr += this_ext_field_cont_len;

			  //指向下一个头部字段
			  next_hdr_type = *p_ext_hdr;
			  p_ext_hdr++;
		  }
	  }else{
		  p_ext_hdr++;
	  }
	}

	return (char *)p_ext_hdr - (char *)gtph;
}

int gtp_entry(struct streaminfo_private *pfstream_pr,void *this_layer_data,int thread_num, 
		unsigned char routedir, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr)
{
	/*
		创建gtp层结构, 分别记录C2S, S2C方向的地址, 
	*/
    struct streamindex tmp_index;
    struct streamindex *ptmp=&tmp_index;
    struct streaminfo_private *pstream_pr = &ptmp->stream;
    struct streaminfo *pstream = &pstream_pr->stream_public;
    struct layer_addr_gtp gtpaddr;
    const struct gtp_hdr *p_gtd_hdr;
    int ret = PASS;
    char *next_layer_hdr;
    int next_layer_offset;
    int gtp_hdr_len;
    sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[thread_num]->sys_stat;

	local_sys_stat->count_per_layer[ADDR_TYPE_GPRS_TUNNEL][pfstream_pr->layer_index+1]++; 
	local_sys_stat->length_per_layer[ADDR_TYPE_GPRS_TUNNEL][pfstream_pr->layer_index+1] += raw_pkt->raw_pkt_len - offset_to_raw_pkt_hdr;
	

    /* 之前已经通过协议识别插件识别过, 所以在entry()里不用再次判断 */
    p_gtd_hdr = (const struct gtp_hdr *)((char *)this_layer_data + sizeof(struct mesa_udp_hdr));

    /* 仅处理T-PDU类型的数据面信息，控制面不认为是GTP隧道*/
    if(p_gtd_hdr->msg_type != GTP_MSG_TYPE_T_PDU)
    {
        sapp_runtime_log(RLOG_LV_DEBUG, "GTP layer msg_type not T_PDU, %x !\n", p_gtd_hdr->msg_type);
        return PASS;
    }

	gtp_hdr_len = deal_gtp_calc_gtp_hdr_len(p_gtd_hdr);
	if(gtp_hdr_len < 0){
		sapp_runtime_log(RLOG_LV_DEBUG, "get gtp header len error, flags:0x%x, msg_type:0x%x, len:%u\n", 
						p_gtd_hdr->flags, p_gtd_hdr->msg_type, ntohs(p_gtd_hdr->len));
		return PASS;
	}

    local_sys_stat->count[SAPP_STAT_TUNNEL_GTP]++;

    memset(&tmp_index, 0, sizeof(struct streamindex));

    /* GTP地址C2S, S2C方向独立, 无法靠当前包地址区分dir, 每次栈里的变量都存储于source方向, 即C2S方向,  
       创建流时, 如果需要reverse拷贝, 则将source, dest颠倒, 否则直接memcpy到堆里的addr.
     */
    gtpaddr.teid_c2s = p_gtd_hdr->teid;
    gtpaddr.teid_s2c = 0;
    pstream->curdir = DIR_C2S;

    pstream->addr.paddr = &gtpaddr;
    pstream->addr.addrtype = ADDR_TYPE_GPRS_TUNNEL;
    pstream->addr.addrlen = sizeof(struct layer_addr_gtp); /* 此处使用内存结构体长度, 而非网络头部struct gtp_hdr */

    pstream_pr->addr_use_as_hash = 1; /* gtp层的TEID和外层ip,port可能会变化, 靠特殊函数checkstreamorder_for_gtp_tunnel()比较 */
    pstream_pr->need_update_opposite_addr = 1;//需要更新对侧信息

    pstream_pr->offset_to_raw_pkt_hdr = (unsigned short)offset_to_raw_pkt_hdr;
    pstream_pr->raw_pkt = raw_pkt;
    pstream_pr->layer_dir = pfstream_pr->layer_dir;  

    pstream_pr->layer_index = pfstream_pr->layer_index + 1;

    pstream->pfather=&pfstream_pr->stream_public;
    pstream_pr->pfather_pr=pfstream_pr;
    pstream->type=STREAM_TYPE_NON;
    pstream->routedir=routedir;
    pstream->threadnum=(UCHAR)thread_num;

    next_layer_hdr = (char *)p_gtd_hdr + gtp_hdr_len;
    next_layer_offset = offset_to_raw_pkt_hdr + gtp_hdr_len;

	int left_pkt_len = raw_pkt->raw_pkt_len - next_layer_offset;
    if((*next_layer_hdr & 0xF0) == 0x40)
    {
        const struct iphdr  *ip4_hdr = (struct iphdr *)next_layer_hdr;
        if(left_pkt_len < 20 || ntohs(ip4_hdr->tot_len) > left_pkt_len)
        {
            local_sys_stat->count[SAPP_STAT_RCV_UNKNOWN]++;
			local_sys_stat->count[SAPP_STAT_RCV_UNKNOWN]+= raw_pkt->raw_pkt_len;	
			((raw_pkt_t *)raw_pkt)->diagnose_error_to_dump = 1;
            sapp_runtime_log(20, "GTP entry: illegal left Ipv4 len %d, expect total len %d!\n", left_pkt_len, ntohs(ip4_hdr->tot_len));
            return PASS;
        }
        ret = ipv4_entry(pstream_pr,next_layer_hdr,thread_num,routedir,raw_pkt, next_layer_offset);
    }
    else if((*next_layer_hdr & 0xF0) == 0x60)
    {
    	const struct mesa_ip6_hdr  *ip6_hdr = (struct mesa_ip6_hdr *)next_layer_hdr;
    	if(left_pkt_len < sizeof(struct mesa_ip6_hdr) || ntohs(ip6_hdr->ip6_payload_len) > left_pkt_len){
            local_sys_stat->count[SAPP_STAT_RCV_UNKNOWN]++;
			local_sys_stat->count[SAPP_STAT_RCV_UNKNOWN]+= raw_pkt->raw_pkt_len;	
			((raw_pkt_t *)raw_pkt)->diagnose_error_to_dump = 1;
            sapp_runtime_log(10, "GTP entry: illegal left Ipv6 len %d, expect total len %d!\n", left_pkt_len, ntohs(ip6_hdr->ip6_payload_len));
			return PASS;
    	}
        ret = ipv6_entry(pstream_pr,next_layer_hdr,thread_num,routedir,raw_pkt, next_layer_offset);
    }
    else
    {
        sapp_runtime_log(20, "GTP next layer not IPv4 or IPv6, ignore this pkt!\n");
        return PASS;
    }
    return ret;
}

//仅识别GTP-U协议，用于进行隧道处理
static int identify_gtp(const struct streaminfo *pstream,const char *payload, unsigned int udp_payload_len)
{
    if (udp_payload_len >= sizeof(struct gtp_hdr))
    {
        unsigned int gtp_u = (2152);
        unsigned int gtp_v0 = (3386);

        unsigned short dest = 0, source = 0;

        if (pstream->addr.addrtype == __ADDR_TYPE_IP_PAIR_V6
            || pstream->addr.addrtype == ADDR_TYPE_IPV6) {
            dest = ntohs(pstream->addr.ipv6->dest);
            source = ntohs(pstream->addr.ipv6->source);
        } else {
            dest = ntohs(pstream->addr.ipv4->dest);
            source = ntohs(pstream->addr.ipv4->source);
        }

        if ((source == gtp_u) || (dest == gtp_u) || ((source == gtp_v0) || (dest == gtp_v0))) {
            struct gtp_hdr *gtp = (struct gtp_hdr *) payload;
            unsigned short gtp_version = (gtp->flags & 0xE0) >> 5;
            if ((gtp_version == 0) || (gtp_version == 1))
            {
                unsigned short message_len = ntohs(gtp->len);
                /* NOTE: gtp->len不包括gtp头部固定长度(8字节), 只包括扩展头部和负载 */
                if (message_len == (udp_payload_len - sizeof(struct gtp_hdr))) {
                    if(gtp_version == 1)
                    {
                        return 1;
                    }
                    else
                    {
                        sapp_runtime_log(20, "not support GTP v%d yet!\n", gtp_version); 
                        return 0;
                    }
                }
            }
        }
    }
    return 0;
}

/*
	内置插件, 
	用于识别当前UDP流是否是隧道.
	如果是隧道, 在streaminfo_private->stream_carry_up_layer_tunnel_type中设置标记.
*/
char udp_gtp_identify_entry(const struct streaminfo *pstream, const void *this_hdr, const void *raw_pkt, void **pme)
{
    struct streaminfo_private *pstream_pr = (struct streaminfo_private *)pstream;
    if(1 == identify_gtp(pstream, (char *)this_hdr+sizeof(struct mesa_udp_hdr), 
    					pstream_pr->raw_pkt->raw_pkt_len - ((const char *)this_hdr - (const char*)pstream_pr->raw_pkt->raw_pkt_data) - sizeof(struct mesa_udp_hdr)))
    {
        pstream_pr->stream_carry_up_layer_tunnel_type |= STREAM_TUNNEL_GPRS_TUNNEL;
    }
	return APP_STATE_DROPME; /* 每个流只看第一个包, 不管是否GTP隧道, 后续都不再处理了 */
}


#ifdef __cplusplus
}
#endif


