
#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"
#include "sapp_declaration.h"

extern int ipv4_entry(struct streaminfo_private *pfstream, const void *this_layer_data, int thread_num, 
			unsigned char routedir, const raw_pkt_t *raw_pkt, int);
extern int ipv6_entry(struct streaminfo_private *pfstream, const void *this_layer_data, int thread_num, 
			unsigned char routedir, const raw_pkt_t *raw_pkt, int);

#define TEREDO_DEFAULT_PORT	(3544)		
		
int guess_if_teredo(const struct streaminfo *pstream,  struct mesa_udp_hdr *udphdr)
{
	struct mesa_ip6_hdr *ip6hdr;
	int udp_payuload_len;

	if(ADDR_TYPE_IPV4 != pstream->addr.addrtype){
		return 0; /* teredo只承载于IPv4 */
	}

	 /* 2018-03-13 lijia close, 某些Teredo隧道使用非标准端口, 逃避检测, 不再判断端口 */
#if 0	 
	if((TEREDO_DEFAULT_PORT != ntohs(udphdr->uh_sport))
	&& (TEREDO_DEFAULT_PORT != ntohs(udphdr->uh_dport))){
		return 0;
	}
#endif

    udp_payuload_len = ntohs(udphdr->uh_ulen) - sizeof(struct mesa_udp_hdr);
    if(udp_payuload_len < (int)sizeof(struct mesa_ip6_hdr)){ /* 负载还不够一个完整IPv6包头 */
        return 0;
    }

    ip6hdr = (struct mesa_ip6_hdr *)((char *)udphdr + sizeof(struct mesa_udp_hdr ));
	if(ip6hdr->ip6_flags[0] != 0x60){
        return 0;
    }

	/* NOTE: RFC4380-Page12, ipv6源地址的第11-12字节, 与0xFFFF异或之后的值, 即底层UDP的源端口 */
	if((ip6hdr->ip6_src.s6_addr16[5] ^ 0xFFFF) != udphdr->uh_sport){
		return 0;
	}
	/* NOTE: RFC4380-Page12, ipv6地址的第13-16字节, 与0xFFFFFFFF异或之后的值, 即底层IPv4地址,
		但IP-MAP规则用于Internet外网地址, NAT内部私有地址不适用, 读包测试可能无法识别, 
		所以暂时关闭.
	*/
#if 0	
	const struct streaminfo_private *pstream_pr  = (struct streaminfo_private *)pstream;
	const struct mesa_ip4_hdr *ip4hdr = (const struct mesa_ip4_hdr *)((char *)udphdr - pstream_pr->offset_to_ip_hdr);
	if(((ip6hdr->ip6_src.s6_addr32[3] ^ 0xFFFFFFFF) != ip4hdr->ip_src.s_addr)
	 && ((ip6hdr->ip6_dst.s6_addr32[3] ^ 0xFFFFFFFF) != ip4hdr->ip_dst.s_addr)){
		return 0;
	} 
#endif

	return 1;
}

int teredo_entry(struct streaminfo_private *pfstream_pr,void *this_layer_data,int thread_num, 
		unsigned char routedir, const raw_pkt_t *raw_packet, int offset_to_raw_pkt_hdr)
{
#if COMPAT_PAPP_FOR_BENCHMARK
	return PASS;
#endif
	struct mesa_udp_hdr *udphdr;
	char *next_layer_hdr;
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[thread_num]->sys_stat;

	udphdr = (struct mesa_udp_hdr *)(this_layer_data);

#if 0 /* 在插件udp_teredo_identify_entry中已经判断过, 不必重复验证 */
	if(unlikely(guess_if_teredo(&pfstream_pr->stream_public, udphdr) == 0)){
		return PASS;
	}
#endif	

	//next_layer_hdr = (char *)udphdr + sizeof(struct mesa_udp_hdr);
	next_layer_hdr = (char *)udphdr + sizeof(struct mesa_udp_hdr);
	struct teredo_auth_hdr *p_teredo_hdr;
	int tmp_hdr_len = 0;
	while((*next_layer_hdr & 0xF0) != 0x60)
	{
		p_teredo_hdr = (struct teredo_auth_hdr *)next_layer_hdr;
		if(p_teredo_hdr->flags == ntohs(TEREDO_AUTH_HDR_FLAG))
		{
			//rfc4380 5.1.1 teredo 负载0x0001时为Teredo authentication headers，需要跳过
			tmp_hdr_len += sizeof(struct teredo_auth_hdr) + ntohs(p_teredo_hdr->au_len) + ntohs
					(p_teredo_hdr->id_len) + 8 + 1;
			next_layer_hdr += tmp_hdr_len;
		}
		else if(p_teredo_hdr->flags == ntohs(TEREDO_INDICATION_HDR_FLAG))
		{
			//rfc4380 teredo 负载0x0000时为Teredo indication headers，需要跳过
			next_layer_hdr += TEREDO_INDICATION_HDR_LEN;
		}
		else
		{
			sapp_runtime_log(20, "unsupport teredo hdr:0x%u!\n", *(unsigned int *)(next_layer_hdr));
			return -1;
		}
	}
	local_sys_stat->count[SAPP_STAT_TUNNEL_TEREDO]++;

	/* NOTE: Teredo实际传输时没有包结构, 也就无需分配stream结构, 直接跳到Ipv6层即可 */
	return ipv6_entry(pfstream_pr, next_layer_hdr, thread_num, routedir, raw_packet, offset_to_raw_pkt_hdr);
}


#ifdef __cplusplus
}
#endif


