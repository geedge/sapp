/* 详见: RFC1701, RFC2784 */
#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"

#define GRE_DEBUG    	(0)

#if GRE_DEBUG
#define GRE_PRINT(fmt, args...) printf(fmt, ##args)
#else
#define GRE_PRINT(fmt, args...) 
#endif
#define GRE_PRO_IPV4	(0x0800)
#define GRE_PRO_IPV6	(0x86DD)
#define GRE_PRO_ARP	(0x0806)
#define GRE_PRO_PPP	(0x880B)

extern int pptp_entry(struct streamindex *pindex, const void *this_layer_data, int thread_num, 
			unsigned char routedir, const raw_pkt_t *raw_pkt, int, const struct mesa_gre_hdr *, int gre_hdr_len);	

static inline int calc_gre_hdr_len_v0(const struct mesa_gre_base_hdr_v0  *gre_base_hdr_v0)
{
	int gre_hdr_len = sizeof(struct mesa_gre_base_hdr_v0);

	if(gre_base_hdr_v0->checksum_flag || gre_base_hdr_v0->route_flag){
		gre_hdr_len += sizeof(short) * 2;	/* checksum and offset  */	
	}

	if(gre_base_hdr_v0->key_flag){
		gre_hdr_len += sizeof(int );
	}
	
	if(gre_base_hdr_v0->seq_flag){
		gre_hdr_len += sizeof(int );
	}

	return gre_hdr_len;	
}

static inline int calc_gre_hdr_len_v1(const struct mesa_gre_base_hdr_v1  *gre_base_hdr_v1)
{
	int gre_hdr_len = sizeof(struct mesa_gre_base_hdr_v1);

	if(gre_base_hdr_v1->checksum_flag != 0){
		GRE_PRINT("error! in gre version1, checksum flag not zero!\n");
		return -1;
	}

	if(gre_base_hdr_v1->route_flag != 0){
		GRE_PRINT("error! in gre version1, route flag not zero!\n");
		return -1;
	}

	if(gre_base_hdr_v1->recur != 0){
		GRE_PRINT("error! in gre version1, recur flag not zero!\n");
		return -1;
	}
	
	if(gre_base_hdr_v1->strict_src_route_flag != 0){
		GRE_PRINT("error! in gre version1, strict_src_route flag not zero!\n");
		return -1;
	}
	
	if(ntohs(gre_base_hdr_v1->protocol) != GRE_PRO_PPP){
		GRE_PRINT("error! in gre version1, protocol not 0x%x!\n", GRE_PRO_PPP);
		return -1;
	}	

	gre_hdr_len += sizeof(short) * 2;	/* payload_len and callid */
	
	if(gre_base_hdr_v1->seq_flag){
		gre_hdr_len += sizeof(int);
	}
	
	/* version 1 has ack number */
	if(gre_base_hdr_v1->ack_flag){
		gre_hdr_len += sizeof(int);
	}	

	return gre_hdr_len;
}

int calc_gre_hdr_len(const struct mesa_gre_hdr *gre_hdr)
{
	int gre_hdr_len = -1;

	if(0 == gre_hdr->gre_base.version){
		gre_hdr_len = calc_gre_hdr_len_v0(&gre_hdr->gre_base);
	}else if(1 == gre_hdr->gre_base.version){
		gre_hdr_len = calc_gre_hdr_len_v1((const struct mesa_gre_base_hdr_v1 *)&gre_hdr->gre_base);
	}else{
		gre_hdr_len = -1;
	}

	return gre_hdr_len;
}

static int set_gre_hdr_ver0(struct mesa_gre_hdr *stack_gre_addr, const struct mesa_gre_hdr *net_gre_addr)
{
	struct mesa_gre_extend_hdr *stack_gre_ext = &stack_gre_addr->gre_extend;
	const struct mesa_gre_base_hdr_v0 *net_gre_base = &net_gre_addr->gre_base;
	const char *net_ext_hdr_value = (const char *)(&net_gre_addr->gre_extend);
	//const struct gre_source_route_entry_hdr *rse_hdr;

	if(net_gre_base->checksum_flag || net_gre_base->route_flag){
		stack_gre_ext->checksum = *((unsigned short *)net_ext_hdr_value);
		net_ext_hdr_value += sizeof(short);

		/* 如果checksum存在, 则offset也必存在 */
		stack_gre_ext->offset = *((unsigned short *)net_ext_hdr_value);
		net_ext_hdr_value += sizeof(short);		
	}

	if(net_gre_base->key_flag){
		stack_gre_ext->key = *((unsigned int *)net_ext_hdr_value);
		net_ext_hdr_value += sizeof(int);
	}
	
	if(net_gre_base->seq_flag){
		stack_gre_ext->seq_num = *((unsigned int *)net_ext_hdr_value);
		net_ext_hdr_value += sizeof(int);
	}
	
	/* SRE信息在GRE头部的最后, 因为不定长, 不定数量 */
	if(net_gre_base->route_flag){
		//rse_hdr = (const struct gre_source_route_entry_hdr *)net_ext_hdr_value;
		//TODO 1, copy SRE
		GRE_PRINT("found GRE SRE data, but not parse yet, TODO!\n");
		return -1;
	}

	return sizeof(struct mesa_gre_base_hdr_v1) + (net_ext_hdr_value - (char *)&net_gre_addr->gre_extend);	
}

static int set_gre_hdr_ver1(struct mesa_gre_hdr *stack_gre_addr, const struct mesa_gre_hdr *net_gre_addr)
{
	//struct mesa_gre_base_hdr_v1 *stack_gre_base = (struct mesa_gre_base_hdr_v1 *)&stack_gre_addr->gre_base;
	struct mesa_gre_extend_hdr *stack_gre_ext = &stack_gre_addr->gre_extend;
	const struct mesa_gre_base_hdr_v1 *net_gre_base = (struct mesa_gre_base_hdr_v1 *)&net_gre_addr->gre_base;
	//const struct mesa_gre_extend_hdr *net_gre_ext = &net_gre_addr->gre_extend;
	const char *net_ext_hdr_value = (const char *)(&net_gre_addr->gre_extend);

	if(net_gre_base->checksum_flag != 0){
		GRE_PRINT("error! in gre version1, checksum flag not zero!\n");
		return -1;
	}

	if(net_gre_base->route_flag != 0){
		GRE_PRINT("error! in gre version1, route flag not zero!\n");
		return -1;
	}

	if(net_gre_base->recur != 0){
		GRE_PRINT("error! in gre version1, recur flag not zero!\n");
		return -1;
	}
	
	if(net_gre_base->strict_src_route_flag != 0){
		GRE_PRINT("error! in gre version1, strict_src_route flag not zero!\n");
		return -1;
	}
	
	if(ntohs(net_gre_base->protocol) != GRE_PRO_PPP){
		GRE_PRINT("error! in gre version1, protocol not 0x%x!\n", GRE_PRO_PPP);
		return -1;
	}	

	stack_gre_ext->payload_len = *((unsigned short *)net_ext_hdr_value);
	net_ext_hdr_value += sizeof(short);	
	
	stack_gre_ext->call_id = *((unsigned short *)net_ext_hdr_value);
	net_ext_hdr_value += sizeof(short);	
	
	if(net_gre_base->seq_flag){
		stack_gre_ext->seq_num = *((unsigned int *)net_ext_hdr_value);
		net_ext_hdr_value += sizeof(int);
	}
	
	/* version 1 has ack number */
	if(net_gre_base->ack_flag){
		stack_gre_ext->ack_num = *((unsigned int *)net_ext_hdr_value);
		net_ext_hdr_value += sizeof(int);
	}

	return sizeof(struct mesa_gre_base_hdr_v1) + (net_ext_hdr_value - (char *)&net_gre_addr->gre_extend);
}

int set_gre_hdr(struct mesa_gre_hdr *stack_gre_addr, const void *this_layer_data)
{
	int gre_hdr_len = 0;
	const struct mesa_gre_hdr *net_gre_addr = (const struct mesa_gre_hdr *)this_layer_data;

	memcpy(&stack_gre_addr->gre_base, &net_gre_addr->gre_base, sizeof(struct mesa_gre_base_hdr_v0));
	memset(&stack_gre_addr->gre_extend, 0, sizeof(struct mesa_gre_extend_hdr));
	
	if(0 == net_gre_addr->gre_base.version){
		gre_hdr_len = set_gre_hdr_ver0(stack_gre_addr, net_gre_addr);
	}else if(1 == net_gre_addr->gre_base.version){
		gre_hdr_len = set_gre_hdr_ver1(stack_gre_addr, net_gre_addr);
	}else{
		//TODO 1, 未知版本
		GRE_PRINT("Unknown gre hdr version:%d\n", net_gre_addr->gre_base.version);
		gre_hdr_len = -1;
	}

	return gre_hdr_len;
}

int gre_entry(struct streaminfo_private *pfstream_pr,const void *this_layer_data,int thread_num, 
						unsigned char routedir, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr)
{
#if COMPAT_PAPP_FOR_BENCHMARK
	return PASS;
#endif
	int ret = PASS;
	struct streamindex tmp_index;
	struct streamindex *ptmp=&tmp_index;
	struct streaminfo_private *pstream_pr = &ptmp->stream;
	struct streaminfo *pstream = &pstream_pr->stream_public;		
	struct mesa_gre_hdr gre_addr;
	int gre_hdr_len = 0; /* GRE地址的实际长度, 可变 */
	char *next_layer_hdr; 
	int next_layer_offset; 
	 
	memset(ptmp,0,sizeof(struct streamindex));
	//set_gre_id(&addr, (unsigned short *)this_layer_data);
	gre_hdr_len = set_gre_hdr(&gre_addr, this_layer_data);
	if(gre_hdr_len < 0){
		return PASS; /* 无法识别的包 */
	}
	
	next_layer_hdr = (char *)this_layer_data+gre_hdr_len;
	if(next_layer_hdr-(char *)raw_pkt->raw_pkt_data >= raw_pkt->raw_pkt_len){ /* 有些GRE包只有ACK标志, 没有负载, 类似TCP */
		return PASS;
	}

	if((1 == gre_addr.gre_base.version) && (0 == gre_addr.gre_extend.payload_len)){ /* 负载为0, 不再处理 */
		return PASS;
	}
	
	next_layer_offset = gre_hdr_len + offset_to_raw_pkt_hdr;
	pstream->addr.paddr = &gre_addr;
	pstream->addr.addrtype = ADDR_TYPE_GRE;
	pstream->addr.addrlen = sizeof(struct mesa_gre_hdr); 
	
	/* 
		TODO 1:
		GRE层callid只在当前包存在, 但另一个方向的callid获取不到, 目前还没有GRE流,
		GRE层双向格式可以不相同, 序号等也实时变化, 没有可以做为唯一标识的变量, 不做地址比较 
		仅用于跳包, 和发送RST构造包时使用.	
	*/
	pstream_pr->addr_use_as_hash = 0; 	
	pstream_pr->offset_to_raw_pkt_hdr = offset_to_raw_pkt_hdr;
	pstream_pr->raw_pkt = raw_pkt;
	
	pstream->pfather=&pfstream_pr->stream_public;
	pstream->type=STREAM_TYPE_NON;
	pstream->routedir=routedir;
	pstream->threadnum=thread_num;

	/* TODO 1:
		GRE包格式解析, 不定长, 不定项!
		基于GRE层发送RST包时, C2S与S2C是不同的, 需要类似TCP层保留双向的信息,
		可能需要根据下层IP地址, 标识一个GRE虚拟通道, 本层还需要HASH查找?!
		发送RST的预留包头空间长度也需要动态计算.
	*/

	//gre_pro_type=*((unsigned short *)((char *)this_layer_data + 2));

	switch(ntohs(gre_addr.gre_base.protocol))
	{
		case GRE_PRO_IPV4:
			((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offset;
			ret=ipv4_entry(pstream_pr,(const void *)next_layer_hdr,thread_num,routedir,raw_pkt,next_layer_offset);
			break;

		case GRE_PRO_IPV6:
			((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offset;
			ret=ipv6_entry(pstream_pr,(const void *)next_layer_hdr,thread_num,routedir,raw_pkt,next_layer_offset);
		break;
		
		case GRE_PRO_PPP:
			/* GRE和PPP合并为一层, 对插件的流、地址类型改为PPTP, 和PPP层共用一个pindex结构 */
			////((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offset;
			ret=pptp_entry(&tmp_index,(const void *)next_layer_hdr,thread_num,routedir,raw_pkt,next_layer_offset, &gre_addr, gre_hdr_len);		
		break;
		default:
			ret = PASS;
			GRE_PRINT("Unknown gre protocol\n");
			break;
	}

	return ret;
}

#ifdef __cplusplus
}
#endif

