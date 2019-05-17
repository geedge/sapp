/*
 *  Description:
 *      IPv6 implement.
 *
 *  Author:    Li Jia<lijia@software.ict.ac.cn>
 *  Date:      2012-05-25
 *  Version:   0.1
 */
 
#include "sapp_api.h"
#include "sapp_private_api.h"

#ifdef __cplusplus
extern "C" {
#endif

static struct frag_manage *g_ipv6_frag_manage = NULL;
static unsigned int FRAG_IP6_RANDOM;
extern int g_packet_io_ipv6_switch;
extern int g_packet_io_thread_num;
extern void raw_frags_list_free_one(int thread_seq, void *project_req_value);
int update_global_ip_frag_list(raw_ipfrag_list_t *list_head, int thread_num, int type);
extern int dealipv6tcppkt(struct streamindex *pfindex, const struct mesa_ip6_hdr *this_iphdr,
	char *data, int datalen, int thread_num,unsigned char routedir, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr);
extern int dealipv6udppkt(struct streamindex *pfindex,const struct mesa_ip6_hdr *a_packet,
	char *data, int thread_num,unsigned char routedir, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr);

static uint32 ipv6_frag_hash_algo(uint32 id, const struct in6_addr *saddr,
			     		const struct in6_addr *daddr, uint32 frand)
{
	uint32 c;

	c = frag_common_hash(saddr->s6_addr32[0],
			 		 saddr->s6_addr32[1],
			 		 saddr->s6_addr32[2],
			 		 frand);

	c = frag_common_hash(saddr->s6_addr32[3],
			 	 	 daddr->s6_addr32[0],
			 		 daddr->s6_addr32[1],
			 		 c);

	c = frag_common_hash(daddr->s6_addr32[2],
			  		  daddr->s6_addr32[3],
			  		  id,
			  		  c);

	return c;
}


#if USE_MESA_STREAM_HASH
static int ipv6_frag_key_cmp_cb(const uchar * key1, uint size1, const uchar * key2, uint size2)
{
	int ret;
	const struct ipv6_frag_key *ipv6_fkey1 = (const struct ipv6_frag_key *)key1;
	const struct ipv6_frag_key *ipv6_fkey2 = (const struct ipv6_frag_key *)key2;

	if(!(0 == memcmp(&ipv6_fkey1->ip6_src, &ipv6_fkey1->ip6_src, sizeof(struct in6_addr)))
	 && (0 == memcmp(&ipv6_fkey1->ip6_dst, &ipv6_fkey1->ip6_dst, sizeof(struct in6_addr)))
	 && (ipv6_fkey1->identification == ipv6_fkey2->identification)){
		return -1;
	}

	ret = MESA_stream_list_cmp(ipv6_fkey1->pfstream_pr, ipv6_fkey2->pfstream_pr);

	return ret;
}

static unsigned int ipv6_frag_hash_index(const MESA_htable_handle table, const uchar * key, unsigned int size)
{
	struct ipv6_frag_key *ipv6_key = (struct ipv6_frag_key *)key;

	return ipv6_frag_hash_algo(ipv6_key->identification,
						  	   &ipv6_key->ip6_src,
						  	   &ipv6_key->ip6_dst,
						  	   FRAG_IP6_RANDOM);					  	   
}

static uchar * ipv6_frag_key_dup(const uchar *key, uint key_size)
{
	struct ipv6_frag_key *new_frag_key, *raw_frag_key;
	int tid;

	raw_frag_key = (struct ipv6_frag_key *)key;
	tid = raw_frag_key->pfstream_pr->stream_public.threadnum;

	/* 此函数无法获取线程号, 所以使用malloc, 同理函数中也要使用free */
	new_frag_key = (struct ipv6_frag_key *)dictator_malloc(tid, sizeof(struct ipv6_frag_key));

	memcpy(&new_frag_key->ip6_src, &raw_frag_key->ip6_src, sizeof(struct in6_addr));
	memcpy(&new_frag_key->ip6_dst, &raw_frag_key->ip6_dst, sizeof(struct in6_addr));
	new_frag_key->identification = raw_frag_key->identification;

	new_frag_key->pfstream_pr = MESA_stream_list_dup(raw_frag_key->pfstream_pr, 0);

	return (uchar *)new_frag_key;
}

static void ipv6_frag_key_free(uchar *key, uint key_size)
{
	struct ipv6_frag_key *frag_key;
	int tid;
	
	if(NULL == key){
		return;
	}

	frag_key = (struct ipv6_frag_key *)key;
	tid = frag_key->pfstream_pr->stream_public.threadnum;

	MESA_stream_list_free(frag_key->pfstream_pr);
	
	dictator_free(tid, frag_key);
}

void ipv6_frag_ipq_free_no_iph(void *data)
{
	struct frag_ipq *ipq = (struct frag_ipq *)data;
	struct ip_frags *frag, *next;
	int thread_num = ipq->thread_num;

	/* Release all fragment data. */
	frag = ipq->fragments;
	while(frag != NULL) 
	{
    		next = frag->next;
		dictator_free(thread_num, frag);
		frag = next;
	}

	if(ipq->private_info && ipq->private_len)
	{
		dictator_free(thread_num, ipq->private_info);
	}

#if (0 == HIGH_PERF)
	raw_frags_list_free_one(thread_num, ipq->ipfrag_list);
#endif	
	ipq->ipfrag_list = NULL;

	dictator_free(thread_num, ipq);

	return;
}

static void ipv6_frag_ipq_free_all(void *data)
{
	struct frag_ipq *ipq = (struct frag_ipq *)data;

	/* 因重组错误删除时, 要释放new_iph内存 */
	if(ipq->new_iph){
		dictator_free(ipq->thread_num, ipq->new_iph);
	}
	ipv6_frag_ipq_free_no_iph(data);

	return;
}

#endif

static inline int checkipv6pkt(const struct mesa_ip6_hdr * iph, int payload_len, int raw_pkt_len)
{
	unsigned char ip_proto;
	
	if((iph->ip6_flags[0] & 0xF0) != 0x60){
		return -1;
	}
	
	switch(iph->ip6_nxt_hdr){
#if 0	
		case  NEXTHDR_TCP			:  
		case  NEXTHDR_UDP			:  
		case  NEXTHDR_IPV6			:
		case  NEXTHDR_HOP			:  
		case  NEXTHDR_IPIP			:
		case  NEXTHDR_ROUTING		:  
		case  NEXTHDR_ESP			:  
		case  NEXTHDR_AUTH		:
		case  NEXTHDR_ICMP			:
		case  NEXTHDR_NONE		:
		case  NEXTHDR_DEST			:
		case  NEXTHDR_MOBILITY	:
			break;
#endif
		case  NEXTHDR_FRAGMENT	:	
			/* NOTE: 因为IPv6分片重组后, 又递归调用了ipv6_entry(), 此时不能检测负载长度大于raw_pkt_len, 只有原始分片包可以这么检测 */
			if(payload_len + (int)sizeof(struct mesa_ip6_hdr) > raw_pkt_len){
				sapp_runtime_log(20, "ipv6 packet check error: fragement pkt len:%d, raw_pkt len: %d\n", payload_len, raw_pkt_len);
				return -1;
			}
		break;

		default:
			ip_proto = iph->ip6_nxt_hdr;
			if(ip_proto >= 0x8F){
				sapp_runtime_log(20, "ipv6 packet check error: unknow proto: %u\n", ip_proto);
				return -1;
			}		
			break;
	}

	return 0;
}

/* 2012-05-25 LiJia add */
int ipv6_packet_check(int threadid, int len, struct simple_ip6_hdr *ip6h)
{	
	if (len < (int)sizeof (struct ip6_hdr) 
	|| (ip6h->ip6_flags[0] & 0xF0) != 0x60 
	|| len < ntohs(ip6h->ip6_payload_len) + (int)sizeof(struct ip6_hdr))
	{
		return 0;
	}


	return 1;
}

/* to do: 攻击检测 */
static int ipv6_attack_detect(struct frag_ipq *ipv6_qp)
{
	if(ipv6_qp->attack_flag != 0)
	{
		return ipv6_qp->attack_flag;
	}
	
	if(ipv6_qp->frags_num > IPV6_FRAG_NUM_PER_IPQ)
	{
		ipv6_qp->attack_flag |= IP_FRAG_IGNORE;
		return IP_FRAG_IGNORE;
	}
	
	// to do: 其他策略
	
	return IP_FRAG_OK;
}


int process_ipv6_icmp(struct streaminfo *pfstream, const struct mesa_ip6_hdr *a_packet, 
			char *upper_layer_hdr, int upper_layer_len, int thread_num, unsigned char routedir)
{
#if IPV6_DEBUG
	struct mesa_icmp_echo_hdr *simple_icmp = (struct mesa_icmp_echo_hdr *)upper_layer_hdr;
	if(ICMP6_ECHO_REQUEST == simple_icmp->icmp_type
	  || ICMP6_ECHO_REPLY == simple_icmp->icmp_type)
	{
		
		IPV6_PRINT("===Icmpv6 data length:%d\n", upper_layer_len-8);
		IPV6_PRINT("\tIcmp type:%d\n", simple_icmp->icmp_type);
		IPV6_PRINT("\tIcmp code:%d\n", simple_icmp->icmp_code);
		IPV6_PRINT("\tIcmp checksum:%04x\n", ntohs(simple_icmp->icmp_cksum));
		IPV6_PRINT("\tIcmp id:%04x\n", ntohs(simple_icmp->icd_id));
		IPV6_PRINT("\tIcmp seq:%04x\n", ntohs(simple_icmp->icd_seq));
	}
#endif
	return PASS;
}


#if (0 == USE_MESA_STREAM_HASH)
static unsigned int ipv6_frag_hash_index(void *hash_key)
{
	struct ipv6_frag_key *ipv6_key = (struct ipv6_frag_key *)hash_key;

	return ipv6_frag_hash_algo(ipv6_key->identification,
						  	   &ipv6_key->ip6_src,
						  	   &ipv6_key->ip6_dst,
						  	   (uint32)((long)ipv6_key->pfstream) ^ FRAG_IP6_RANDOM);
}
#endif

/* 
	return value:
	0: key值相同 
	-1:key值不同
*/
int ipv6_frag_hash_cmp(void *hash_key1, void *hash_key2)
{
	return memcmp(hash_key1, hash_key2, sizeof(struct ipv6_frag_key));
}

#if USE_MESA_STREAM_HASH
static struct frag_ipq *ipv6_frag_queue_find(struct streaminfo_private *pstream_pr, 
				struct frag_manage *handle, struct ipv6_frag_key *ip6_frag_key)
{
	struct frag_ipq *frag_ipq;
	int ret;
	
	frag_ipq = (struct frag_ipq *)MESA_htable_search(handle->frag_hash_table,
											   (const uchar *)ip6_frag_key,
											   sizeof(struct ipv6_frag_key));
	if(NULL == frag_ipq){
		frag_ipq = frag_ipq_create(pstream_pr->stream_public.threadnum);
		ret = MESA_htable_add(handle->frag_hash_table,
						 (const uchar *)ip6_frag_key,
						sizeof(struct ipv6_frag_key),
						frag_ipq);
						
		if(ret < 0){
			ipv6_frag_ipq_free_all(frag_ipq); /* 2015-12-01 lijia add, for memory leak */
			return NULL;
		}
	}

	return frag_ipq;
}
#else
static struct frag_ipq *ipv6_frag_queue_find(struct streaminfo_private *pstream_pr, struct frag_manage *handle, 
	const struct mesa_ip6_hdr *raw_packet, struct ipv6_frag_hdr *ipv6_frag_hdr)
{
	struct ipv6_frag_key ip6_key;

	ip6_key.identification = ipv6_frag_hdr->identification;
	ip6_key.pfstream_pr = pstream_pr;
	memcpy(&ip6_key.ip6_src, &raw_packet->ip6_src, sizeof(struct in6_addr));
	memcpy(&ip6_key.ip6_dst, &raw_packet->ip6_dst, sizeof(struct in6_addr));
	ip6_key.__pad__ = 0;

	return frag_ipq_find(handle, &ip6_key, sizeof(struct ipv6_frag_key));
}
#endif

/* 在IPv4环境下，统计出的内存占用经验值 */
static inline int ip6_buff_size(int tot_len) 
{
	return  tot_len > 2048 ? (tot_len > 10240 ? 65576 : 10240) : 2048;
}


#if (USE_MESA_STREAM_HASH==0)
/* 依据超时策略清理内存 */
static void ipv6_frag_mem_clean_by_time(struct frag_manage *handle)
{
	struct frag_ipq *tmp, *next;
	int raw_mem_size = handle->total_mem;
	tmp = handle->lru_head;

	while(tmp && (tmp->create_time + (time_t)IPV6_FRAG_TIMEOUT < g_CurrentTime)) /* timeout */
	{
		next = tmp->lru_next;
		
		frag_ipq_kill(handle, tmp);

		/* 每次只释放一定数量的内存，避免长时间在此函数运行，兼顾其他处理流程 */
		if(raw_mem_size-handle->total_mem >= IPV6_FRAG_MEM_FREE_ONCE)
		{
			break;
		}
		
		tmp = next;
	}
}


/* 依据占用内存数量清理内存 */
static void ipv6_frag_mem_clean_by_size(struct frag_manage *handle)
{
	struct frag_ipq *tmp, *next;
	int raw_mem_size = handle->total_mem;
	tmp = handle->lru_head;
	
	while(tmp && (handle->total_mem >= IPV6_FRAG_MEM_HIGH_THRESH))
	{
		next = tmp->lru_next;
		
		frag_ipq_kill(handle, tmp);

		/* 每次只释放一定数量的内存，避免长时间在此函数运行，兼顾其他处理流程 */
		if(raw_mem_size-handle->total_mem >= IPV6_FRAG_MEM_FREE_ONCE)
		{
			break;
		}
		
		tmp = next;
	}
}


/* 清理内存，按时间和占用内存数量 */
static inline void ipv6_frag_mem_clean(struct frag_manage *handle)
{
	ipv6_frag_mem_clean_by_time(handle);
	ipv6_frag_mem_clean_by_size(handle);
}
#endif

#if USE_MESA_STREAM_HASH
void build_ipv6_frag_key(struct streaminfo_private *pfstream_pr, const struct mesa_ip6_hdr *raw_packet, 
	struct ipv6_frag_hdr *ipv6_frag_hdr, struct ipv6_frag_key *ip6_frag_key)
{
	ip6_frag_key->identification = ipv6_frag_hdr->identification;
	ip6_frag_key->pfstream_pr = pfstream_pr;
	memcpy(&ip6_frag_key->ip6_src, &raw_packet->ip6_src, sizeof(struct in6_addr));
	memcpy(&ip6_frag_key->ip6_dst, &raw_packet->ip6_dst, sizeof(struct in6_addr));
	ip6_frag_key->__pad__ = 0;
}

static void *frag_reassemble_v6(struct frag_manage *handle, struct frag_ipq *ipq, 
								struct ipv6_frag_key *ip6_frag_key)
{
	void *new_iph;

	new_iph = frag_reassemble(handle, ipq);
	
	MESA_htable_del(handle->frag_hash_table, 
					(const uchar *)ip6_frag_key,
					sizeof(struct ipv6_frag_key),
					ipv6_frag_ipq_free_no_iph);	
	return new_iph;				
}
#endif

/* 
	IPv6分片重组入口. 
	参数说明:
		pfstream: 底层流的指针.
		thread_num: 线程ID
		frag_packet: 原始IPv6数据包头指针
		ipv6_frag_hdr: IPv6分片头的指针
		last_hdr_offset: 分片头的前一个包头的next_hdr字段，相对IPv6原始包头的偏移量，
						 重组完成之后，不包含分片头，需要把分片头的前一个包头的next_hdr值改为分片头之后的next_hdr值.
*/
static struct mesa_ip6_hdr *ipv6_defrag(struct streaminfo_private *pstream_pr, 
				int thread_num, const struct mesa_ip6_hdr *frag_packet, 
				struct ipv6_frag_hdr *ipv6_frag_hdr, int last_hdr_offset, const raw_pkt_t *raw_pkt)
{
	struct mesa_ip6_hdr *new_ip6h = NULL;
	struct frag_ipq *ipv6_qp;
	struct ip_frags *prev, *next, *tmp_fg;
	int offset, end;
	int new_buf_size;
	struct ip6_hdr *new_ip6_hdr;
	struct ipv6_frag_private *private_info;
	struct frag_manage *ip6_frag_handle = &g_ipv6_frag_manage[thread_num];
	int attack_flag;
	struct ipv6_frag_key ip6_frag_key;
	//struct streaminfo *pstream = &pstream_pr->stream_public;


#if (USE_MESA_STREAM_HASH==0)
	ipv6_frag_mem_clean(ip6_frag_handle);
#endif

#if USE_MESA_STREAM_HASH
	build_ipv6_frag_key(pstream_pr, frag_packet, ipv6_frag_hdr, &ip6_frag_key);
#endif


#if USE_MESA_STREAM_HASH
	ipv6_qp = ipv6_frag_queue_find(pstream_pr, ip6_frag_handle, &ip6_frag_key);
#else
	ipv6_qp = ipv6_frag_queue_find(pstream_pr, ip6_frag_handle, frag_packet, ipv6_frag_hdr);
#endif	
	if(NULL == ipv6_qp)
	{
		return NULL;
	}

	/* 攻击检测 */
	attack_flag = ipv6_attack_detect(ipv6_qp);
	switch(attack_flag)
	{
		case IP_FRAG_OK:
		break;
		
		case IP_FRAG_INVALID_PACKET:
		case IP_FRAG_IGNORE:
			return NULL;
		break;
		
		case IP_FRAG_DISCARD:
			goto discard_fq;
		break;

		default: /* go on */ 
			break;
	}

#if (0 == HIGH_PERF)		
	frags_list_append(ipv6_qp, raw_pkt, __ADDR_TYPE_IP_PAIR_V6, thread_num);
#endif

	ipv6_qp->frags_num++;

	if(NULL == ipv6_qp->private_info) /* 收到的第一个分片包 */
	{
		ipv6_qp->private_info = frag_malloc(ip6_frag_handle, sizeof(struct ipv6_frag_private));
		ipv6_qp->private_len = sizeof(struct ipv6_frag_private);
		memset(ipv6_qp->private_info, 0, sizeof(struct ipv6_frag_private));
		private_info = (struct ipv6_frag_private *)ipv6_qp->private_info;
		private_info->unfragmentable_len = IPV6_FRAG_RESERVED_HDR_LEN;
	}
	private_info = (struct ipv6_frag_private *)ipv6_qp->private_info;

	offset = ntohs(ipv6_frag_hdr->frag_off) & ~0x7;
	end = offset + (ntohs(frag_packet->ip6_payload_len) -
			((u_int8_t *)(ipv6_frag_hdr + 1) - (u_int8_t *)(frag_packet + 1)));/* lijia comment, 分片头前面有可能还包含其他头部, */

	if(offset >= end)
	{
		goto err;
	}
	if(end > IPV6_MAXPLEN)
	{
		goto err;
	}

	if(!(ipv6_frag_hdr->frag_off & htons(IP6_MF))) /* 最后一个分片包 */ 
	{
		if (end < ipv6_qp->tot_len||
		    ((ipv6_qp->last_in & IP_FRAG_LAST_IN) && end != ipv6_qp->tot_len))
		{    
			goto err;
		}
		ipv6_qp->last_in |= IP_FRAG_LAST_IN;
		ipv6_qp->tot_len = end;		
	}
	else
	{
		if(end & 0x7) /* 不是8的整倍数 */
		{
			goto err;
		}
		if(end > ipv6_qp->tot_len) /* 乱序 */
		{
			if(ipv6_qp->last_in & IP_FRAG_LAST_IN)
			{
				goto err;
			}	
			ipv6_qp->tot_len = end;
		}
	}

	/* Find out which fragments are in front and at the back of us
	 * in the chain of fragments so far.  We must know where to put
	 * this fragment.
	 */
	prev = ipv6_qp->fragments_tail;
	if(!prev || prev->offset < offset) 
	{
		next = NULL;
		goto found;
	}

#if 0 	/* search forward */
	prev = NULL;
	for(next = ipv6_qp->fragments; next != NULL; next = next->next) 
	{
		if(next->offset >= offset)
		{
			break;	/* bingo! */
		}	
		prev = next;
	}
#else	/* search backward, 一般情况下, offset的值都是从小到大，时间复杂度为O(1) */
	next = NULL;
	for(prev = ipv6_qp->fragments_tail; prev != NULL; prev = prev->prev)
	{
		if(prev->offset < offset)
		{
			break;	/* bingo! */
		}	
		next = prev;
	}
#endif


found:
	/* Check for overlap with preceding fragment. */
	if(prev && (prev->end > offset))
	{
		goto discard_fq;
	}
	
	/* Look for overlap with succeeding segment. */
	if(next && (next->offset < end))
	{
		goto discard_fq;
	}

	if(prev && (prev->end == offset)) /* 合并相邻分片信息，无需新建frags结构 */
	{
		prev->end = end;
		goto copy_data;
	}
		
	if(next && (next->offset == end)) /* 合并相邻分片信息，无需新建frags结构 */
	{
		next->offset = offset;
		goto copy_data;
	}

	tmp_fg = frags_create(ip6_frag_handle, offset, end);
	
	/* Insert this fragment in the chain of fragments. */
	tmp_fg->next = next;
	tmp_fg->prev = prev;
	if(next)
	{
		next->prev = tmp_fg;
	}
	else
	{
		ipv6_qp->fragments_tail = tmp_fg;
	}	
	if(prev)
	{
		prev->next = tmp_fg;
	}	
	else
	{
		ipv6_qp->fragments = tmp_fg;
	}	

copy_data:

	ipv6_qp->meat += (end - offset);

	/* The first fragment. */
	if(0 == offset) 
	{
		int this_pkt_unfragmentable_len = (char *)ipv6_frag_hdr - (char *)frag_packet; /* 当前包实际不可分片包头长度 */
		ipv6_qp->last_in |= IP_FRAG_FIRST_IN;
		if(this_pkt_unfragmentable_len > private_info->unfragmentable_len){ /* 实际头部空间超过预留空间 */
			if (end + this_pkt_unfragmentable_len > ipv6_qp->buf_size){  /* 是否需要扩充缓存空间 */
					new_buf_size = ip6_buff_size(end + this_pkt_unfragmentable_len);
					new_ip6h = (struct mesa_ip6_hdr *)frag_malloc(ip6_frag_handle, new_buf_size);
					if(ipv6_qp->meat > 0){ /* meat>0, 之前已经存储过数据, 通常可能是分片乱序, 即先收到后续的分片包 */
						memcpy((char *)new_ip6h + this_pkt_unfragmentable_len, (char *)ipv6_qp->new_iph + private_info->unfragmentable_len,  ipv6_qp->buf_size);
					}
					frag_free(ip6_frag_handle, ipv6_qp->new_iph, ipv6_qp->buf_size);
					ipv6_qp->new_iph = new_ip6h;
					ipv6_qp->buf_size = new_buf_size;
			}
		}
		private_info->unfragmentable_len = this_pkt_unfragmentable_len;
		private_info->raw_next_hdr = ipv6_frag_hdr->nexthdr; /* 记录第一个分片的下一层协议类型 */
		memcpy(ipv6_qp->new_iph, frag_packet, this_pkt_unfragmentable_len);
	}

  	/*If ipq buff is not enough to store current fragment piece, get a bigger one*/
	if(end + private_info->unfragmentable_len > ipv6_qp->buf_size) 
	{
		new_buf_size = ip6_buff_size(end + private_info->unfragmentable_len);
    		new_ip6_hdr = (struct ip6_hdr *)frag_malloc(ip6_frag_handle, new_buf_size);
		memcpy(new_ip6_hdr, ipv6_qp->new_iph, ipv6_qp->buf_size);
		frag_free(ip6_frag_handle, ipv6_qp->new_iph, ipv6_qp->buf_size);
		ipv6_qp->new_iph = new_ip6_hdr;
		ipv6_qp->buf_size = new_buf_size;
	}

	memcpy((char *)ipv6_qp->new_iph + private_info->unfragmentable_len + offset, 
			(char *)ipv6_frag_hdr+sizeof(struct ipv6_frag_hdr),
			end-offset);
	
	if((ipv6_qp->last_in == (IP_FRAG_FIRST_IN | IP_FRAG_LAST_IN)) 
	  && (ipv6_qp->meat == ipv6_qp->tot_len))
	{    
#if (0 == HIGH_PERF)  	
		update_global_ip_frag_list(ipv6_qp->ipfrag_list, thread_num, __ADDR_TYPE_IP_PAIR_V6);
		ipv6_qp->ipfrag_list = NULL;
#endif

		int ip6_payload_len = htons(ipv6_qp->meat); /* 实际数据长度, 不含头部 */
		char raw_next_hdr = private_info->raw_next_hdr;
#if USE_MESA_STREAM_HASH
		new_ip6h = (struct mesa_ip6_hdr *)frag_reassemble_v6(ip6_frag_handle, ipv6_qp, &ip6_frag_key);
#else
		new_ip6h = (struct mesa_ip6_hdr *)frag_reassemble(ip6_frag_handle, ipv6_qp);
#endif
		new_ip6h->ip6_payload_len = ip6_payload_len;
		*((char *)new_ip6h + last_hdr_offset) = raw_next_hdr; /* 更新为第一个包的nexthdr信息 */

		return new_ip6h;
	}	

#if (USE_MESA_STREAM_HASH==0)
	frag_lru_update(ip6_frag_handle, ipv6_qp);
#endif

	return NULL;

discard_fq:

#if USE_MESA_STREAM_HASH
			MESA_htable_del(ip6_frag_handle->frag_hash_table, 
							(const uchar *)&ip6_frag_key,
							sizeof(struct ipv6_frag_key),
							ipv6_frag_ipq_free_all);
#else
	frag_ipq_kill(ip6_frag_handle, ipv6_qp);
#endif

err:

	return NULL;
}


static void set_ipv6_stream(struct streaminfo_private *pfstream_pr, struct streamindex *ptmp, 
	struct layer_addr_ipv6 *ip6_addr, const struct mesa_ip6_hdr *ip6hdr, 
	uchar routedir, int thread_num, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr)
{
	struct streaminfo_private *pstream_pr = &ptmp->stream;
	struct streaminfo *pstream = &pstream_pr->stream_public;
	
	memset(ptmp,0,sizeof(struct streamindex));

	memcpy(ip6_addr->saddr, ip6hdr->ip6_src.s6_addr, IPV6_ADDR_LEN);
	memcpy(ip6_addr->daddr, ip6hdr->ip6_dst.s6_addr, IPV6_ADDR_LEN);
	ip6_addr->source = 0;
	ip6_addr->dest = 0;

	/* LiJia add, 人为用某种算法随意定义一个本层地址的方向, 例如判断memcmp的结果 */
	if(memcmp(ip6_addr->saddr, ip6_addr->daddr, IPV6_ADDR_LEN) >= 0){
		pstream_pr->layer_dir = 1;
		pstream->curdir = DIR_C2S;
	}else{
		pstream_pr->layer_dir = 0;
		pstream->curdir = DIR_S2C;
	}

	pstream->addr.ipv6 = ip6_addr;
	/* 在IP层先设置为__ADDR_TYPE_IP_PAIR_V4, 如果上层是TCP/UDP, 会重新设置为ADDR_TYPE_IPV4, 如果是Ipv6_over_ipv4隧道, 则保留纯IP层地址特性 */
	pstream->addr.addrtype = __ADDR_TYPE_IP_PAIR_V6;
	pstream->addr.addrlen = sizeof(struct layer_addr_ipv6);
	pstream_pr->addr_use_as_hash = 1;
	pstream->addr.pktipfragtype = sapp_global_mthread[thread_num].ipv6_pkt_type_flag;
	//ptmp->stream.p_layer_header = ip6hdr;
//	ptmp->stream.offset_to_raw_pkt_hdr = (char *)ip6hdr - (char *)raw_pkt->raw_pkt_data;
	pstream_pr->offset_to_raw_pkt_hdr = offset_to_raw_pkt_hdr;
	pstream_pr->raw_pkt = raw_pkt; /* 2014-12-30 lijia add */

	pstream->pfather=&pfstream_pr->stream_public;
	pstream->type=STREAM_TYPE_NON;
	pstream->routedir=routedir;
	pstream->threadnum=thread_num;
}


/* 
	IPv6数据包处理入口.
	参数说明:
		pfstream: 底层流的指针.
		a_packet: 原始IPv6数据包头指针
		thread_num: 线程ID
		routedir: 底层包的传输方向
*/
int ipv6_entry(struct streaminfo_private *pfstream_pr, const void *this_layer_hdr, int thread_num, 
		unsigned char routedir, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr)
{
	const struct mesa_ip6_hdr *a_packet = (const struct mesa_ip6_hdr *)this_layer_hdr;
	uint8 next_hdr_type = a_packet->ip6_nxt_hdr;
	uint8 *next_hdr_ptr = (uint8 *)a_packet + sizeof(struct mesa_ip6_hdr);
//	int next_layer_offset;
	int action = PASS;
	int need_free = 0;
	struct mesa_ip6_hdr *new_ip6h = NULL;
	int skip_len = 0, ret;
	const uint8 *last_hdr = &a_packet->ip6_nxt_hdr;
	uint16 payload_len = ntohs(a_packet->ip6_payload_len);
	struct layer_addr_ipv6 ip6_addr;
	struct streamindex tmp_index;
	struct streaminfo *plocal_stream = &tmp_index.stream.stream_public;
#if IPV6_DEBUG
	static unsigned int ipv6_frag_reassemble_num = 0;
#endif

	if(0 == g_packet_io_ipv6_switch){
		static int __print_flag = 1; /* 警告只打印一次, 不狂刷屏 */
		if(__print_flag){
			printf("\033[41m[Warning]recv a IPv6 packet, but IPv6 module is not enable!\033[0m\n");
			__print_flag = 0;
		}
		return PASS;
	}
	
	/* NOTE: 在线环境下发现莫名其妙的IP包, 甚至会死循环, 一定要做头部合法性检查!! */
	if(unlikely(checkipv6pkt(a_packet, (int)payload_len, raw_pkt->raw_pkt_len) < 0)){
		return PASS;
	}

	if((sapp_global_mthread[thread_num].ipv6_pkt_type_flag & PKT_TYPE_IPREBUILD) == 0){
		/* IP分片重组的包会重入ipv6_entry, 不能再计数 */
		g_SysInputInfo[thread_num][PKT_IPV6LEN] += payload_len + sizeof(struct mesa_ip6_hdr);
		g_SysInputInfo[thread_num][PKT_IPV6]++;				
	}

	set_ipv6_stream(pfstream_pr, &tmp_index, &ip6_addr, a_packet, routedir, thread_num, raw_pkt, offset_to_raw_pkt_hdr);

	plocal_stream->addr.pkttype = sapp_global_mthread[thread_num].ipv6_pkt_type_flag;/* 2014-12-25 lijia add */
#if 0 /* to do, gdev check! */
	if(DROP == gdev_check_pkt(__ADDR_TYPE_IP_PAIR_V6, this_layer_hdr)){
		return DROP;
	}
#endif

	/* 2015-02-03 lijia add */
	if(PKT_TYPE_NORMAL == plocal_stream->addr.pkttype){
		stream_process_ipv6_frag(plocal_stream, (const struct ip6_hdr *)this_layer_hdr,
								thread_num, routedir, raw_pkt);
	}

	while(1)
	{
		switch(next_hdr_type)
		{			
			case NEXTHDR_TCP:	
				ret=stream_process_ipv6(plocal_stream,(const struct ip6_hdr *)a_packet,thread_num,routedir,raw_pkt);
				if(ret==DROP){
					goto prosecc_pkt_drop;
				}	

				((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = sizeof(struct mesa_ip6_hdr)+skip_len+offset_to_raw_pkt_hdr;
				action = dealipv6tcppkt(&tmp_index, a_packet, (char *)next_hdr_ptr, 
									payload_len-(next_hdr_ptr-(uint8 *)a_packet)+sizeof(struct mesa_ip6_hdr), 
									thread_num, routedir, raw_pkt, 
									sizeof(struct mesa_ip6_hdr)+skip_len+offset_to_raw_pkt_hdr);
				goto done;
			break;
				
			case NEXTHDR_UDP:		
				ret=stream_process_ipv6(plocal_stream,(const struct ip6_hdr *)a_packet,thread_num,routedir,raw_pkt);
				if(ret==DROP){
					goto prosecc_pkt_drop;
				}	

				((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = sizeof(struct mesa_ip6_hdr)+skip_len+offset_to_raw_pkt_hdr;
				action = dealipv6udppkt(&tmp_index, a_packet, (char *)next_hdr_ptr, thread_num,routedir, raw_pkt,		
									sizeof(struct mesa_ip6_hdr)+skip_len+offset_to_raw_pkt_hdr);
				goto done;
			break;

			case NEXTHDR_FRAGMENT:		
				
				/* 2015-02-03 lijia add */
				plocal_stream->addr.pktipfragtype = PKT_TYPE_IP_FRAG;
				stream_process_ipv6_frag(plocal_stream, (const struct ip6_hdr *)this_layer_hdr,
										thread_num, routedir, raw_pkt);
				new_ip6h = ipv6_defrag(&(tmp_index.stream), thread_num, a_packet, 
						  (struct ipv6_frag_hdr *)next_hdr_ptr, last_hdr-(uchar *)a_packet, raw_pkt); 
#if IPV6_DEBUG
				//printf("ipv6_frag_num: %u\n", ipv6_frag_num++);
#endif
				if(new_ip6h)
				{
					assert(new_ip6h->ip6_nxt_hdr != NEXTHDR_FRAGMENT); /* 强制校验, 分片重组的包不可能再是分片, 就死循环了!! */
					/* 重新设置IP地址信息 */
					set_ipv6_stream(pfstream_pr, &(tmp_index), &ip6_addr, new_ip6h, routedir, thread_num, raw_pkt, skip_len+offset_to_raw_pkt_hdr);
					/* 递归调用自身一次,跳过IPv6的扩展头部,调用上层处理模块 */
#if 0					
					action = ipv6_entry(&(tmp_index.stream), (const void *)new_ip6h, thread_num, routedir, raw_pkt,
#else
					sapp_global_mthread[thread_num].ipv6_pkt_type_flag = PKT_TYPE_IPREBUILD;
					action = ipv6_entry(pfstream_pr, (const void *)new_ip6h, thread_num, routedir, raw_pkt,
#endif
									skip_len+offset_to_raw_pkt_hdr); /* 分片重组的包递归调用自身, 不需加上sizeof(struct mesa_ip6_hdr)头 */
					need_free = 1;
					sapp_global_mthread[thread_num].ipv6_pkt_type_flag = PKT_TYPE_NORMAL;
					IPV6_PRINT("ipv6_frag_reassemble_num: %u\n", ipv6_frag_reassemble_num++);
				}
				goto done;
			break;

			case NEXTHDR_HOP:
			case NEXTHDR_ROUTING:
			case NEXTHDR_AUTH:
			case NEXTHDR_DEST:
				//skip_len = *(next_hdr_ptr + 1) + 1;
				skip_len = (*(next_hdr_ptr + 1))*8 + 8; /* 选项长度以8字节为单位 */			
			break;

			case NEXTHDR_NONE:			
				goto done;
			break;

			case NEXTHDR_ICMP:		
				ret=stream_process_ipv6(plocal_stream,(const struct ip6_hdr *)a_packet,thread_num,routedir, raw_pkt);
				if(ret==DROP){
					goto prosecc_pkt_drop;
				}	
				process_ipv6_icmp(plocal_stream,a_packet,(char *)next_hdr_ptr, 
						 payload_len-(next_hdr_ptr-(uint8 *)a_packet)+sizeof(struct mesa_ip6_hdr), thread_num, routedir);
				goto done;
			break;

			case NEXTHDR_IPIP:
#if COMPAT_PAPP_FOR_BENCHMARK
				return PASS;
#endif			
				ret=stream_process_ipv6(plocal_stream,(const struct ip6_hdr *)a_packet,thread_num,routedir, raw_pkt);
				if(ret==DROP){
					goto prosecc_pkt_drop;
				}					
				/* 2014-12-10 lijia add */
				((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr =  sizeof(struct mesa_ip6_hdr)+skip_len+offset_to_raw_pkt_hdr;
				ret = ipv4_entry(&(tmp_index.stream), (const void *)next_hdr_ptr, thread_num, 
							  routedir, raw_pkt, sizeof(struct mesa_ip6_hdr)+skip_len+offset_to_raw_pkt_hdr);
				goto done;			  
			break;
			
			case NEXTHDR_ESP:
				ret=stream_process_ipv6(plocal_stream,(const struct ip6_hdr *)a_packet,thread_num,routedir, raw_pkt);
				if(ret==DROP){
					goto prosecc_pkt_drop;
				}				

				goto done;

			default:
				g_SysInputInfo[thread_num][PKT_UNKNOWN]++;
				g_SysInputInfo[thread_num][PKT_UNKNOWN_LEN] += raw_pkt->raw_pkt_len;	
				sapp_runtime_log(20, "unsupport Ipv6 protocol:%u!\n", next_hdr_type);			
				goto err_exit;
			break;
		}

		last_hdr = next_hdr_ptr;
		next_hdr_type = *next_hdr_ptr;
		next_hdr_ptr += skip_len;
	}

done:
	if(unlikely(need_free)){
#if (0 == HIGH_PERF)		
		raw_frags_list_free_global(thread_num, __ADDR_TYPE_IP_PAIR_V6);
#endif		
		dictator_free(thread_num, new_ip6h);
	}
	
	return action;

prosecc_pkt_drop:	
err_exit:
	if(need_free)
	{
#if (0 == HIGH_PERF)		
		raw_frags_list_free_global(thread_num, __ADDR_TYPE_IP_PAIR_V6);
#endif		
		dictator_free(thread_num, new_ip6h);
	}
	
	return DROP;
}

#ifdef MESA_HTABLE_VERSION_MACRO
MESA_htable_handle ipv6_frag_htable_create(void)
{
	MESA_htable_handle htable;
	int ret, opt_int;
	
	htable = MESA_htable_born();
	assert(htable != NULL);

	opt_int = 0;
	MESA_htable_set_opt(htable, MHO_THREAD_SAFE, &opt_int, sizeof(int));

	opt_int = 1048576;
	MESA_htable_set_opt(htable, MHO_HASH_SLOT_SIZE, &opt_int, sizeof(int));

	opt_int = 50000;
	MESA_htable_set_opt(htable, MHO_HASH_MAX_ELEMENT_NUM, &opt_int, sizeof(int));

	opt_int = IPV6_FRAG_TIMEOUT;
	MESA_htable_set_opt(htable, MHO_EXPIRE_TIME, &opt_int, sizeof(int));

	opt_int = 0;
	MESA_htable_set_opt(htable, MHO_AUTO_UPDATE_TIME, &opt_int, sizeof(int));

	opt_int = 0;
	MESA_htable_set_opt(htable, MHO_SCREEN_PRINT_CTRL, &opt_int, sizeof(int));

	opt_int = HASH_ELIMINATE_ALGO_LRU;
	MESA_htable_set_opt(htable, MHO_ELIMIMINATE_TYPE, &opt_int, sizeof(int));	

	MESA_htable_set_opt(htable, MHO_CBFUN_KEY_COMPARE, (void *)&ipv6_frag_key_cmp_cb, sizeof(void *));	

	MESA_htable_set_opt(htable, MHO_CBFUN_KEY_TO_INDEX,  (void *)&ipv6_frag_hash_index, sizeof(void *));	

	MESA_htable_set_opt(htable, MHO_CBFUN_DATA_FREE,  (void *)&ipv6_frag_ipq_free_all, sizeof(void *));	

	MESA_htable_set_opt(htable, MHO_CBFUN_COMPLEX_KEY_DUP,  (void *)&ipv6_frag_key_dup, sizeof(void *));	

	MESA_htable_set_opt(htable, MHO_CBFUN_COMPLEX_KEY_FREE,  (void *)&ipv6_frag_key_free, sizeof(void *));	
	
	opt_int = 100;
	MESA_htable_set_opt(htable, MHO_HASH_LIST_COLLIDE_THRESHOLD, &opt_int, sizeof(int));	

	char *err_log = (char *)"./log/ipv6_frag_hash_collide.log";
	MESA_htable_set_opt(htable, MHO_HASH_LOG_FILE, (void *)err_log, strlen(err_log));	
	
	ret = MESA_htable_mature(htable);
	if(ret < 0){
		return NULL;
	}

	return htable;
}
#else
MESA_htable_handle ipv6_frag_htable_create(void)
{
	MESA_htable_create_args_t hargs;
	
	memset(&hargs, 0, sizeof(MESA_htable_create_args_t));
	hargs.thread_safe = 0;
	hargs.recursive = 0;
	hargs.hash_slot_size = 1048576;
	hargs.max_elem_num = 50000;
	hargs.eliminate_type = HASH_ELIMINATE_ALGO_LRU;
	hargs.expire_time = IPV6_FRAG_TIMEOUT;
	hargs.key_comp = ipv6_frag_key_cmp_cb;
	hargs.key2index = ipv6_frag_hash_index;
	hargs.data_free = ipv6_frag_ipq_free_all;
	hargs.data_expire_with_condition = NULL;
	hargs.complex_key_dup = ipv6_frag_key_dup; /* 用于复杂结构的key复制, 如copy一个地址链表 */
	hargs.complex_key_free = ipv6_frag_key_free; /* 删除时释放key的内存资源 */

	return MESA_htable_create(&hargs, sizeof(MESA_htable_create_args_t));
}
#endif

int ipv6_frag_init(int thread_count, uint32 hash_size)
{
	int i;
	
	g_ipv6_frag_manage = (struct frag_manage *)malloc(sizeof(struct frag_manage) * thread_count);
	if(NULL == g_ipv6_frag_manage)
	{
		//to do!
		return -1;
	}
	memset(g_ipv6_frag_manage, 0, sizeof(struct frag_manage) * thread_count);

	for(i = 0; i < thread_count; i++)
	{
		g_ipv6_frag_manage[i].thread_num = i;
		
#if USE_MESA_STREAM_HASH		
		g_ipv6_frag_manage[i].frag_hash_table = ipv6_frag_htable_create();
#else	
		g_ipv6_frag_manage[i].hash_table_size = hash_size;
		g_ipv6_frag_manage[i].frag_hash_table = (struct frag_ipq **)malloc(sizeof(void *) * hash_size);
		memset(g_ipv6_frag_manage[i].frag_hash_table, 0, sizeof(void *) * hash_size);
		g_ipv6_frag_manage[i].hash_index = ipv6_frag_hash_index;
		g_ipv6_frag_manage[i].hash_cmp = ipv6_frag_hash_cmp;
#endif		
	}

	FRAG_IP6_RANDOM = (unsigned int)time(NULL) ^ 0xFEEDBEEF;
	
	return 0;
}

void ipv6_frag_per_thread_exit(int thread_seq)
{
#if USE_MESA_STREAM_HASH	
	MESA_htable_destroy(g_ipv6_frag_manage[thread_seq].frag_hash_table, NULL);
#endif	
}

void ipv6_frag_exit(void)
{
#if USE_MESA_STREAM_HASH	
	int i;

	for(i = 0; i < g_packet_io_thread_num; i++){
		MESA_htable_destroy(g_ipv6_frag_manage[i].frag_hash_table, NULL);
	}
#endif	
}

#ifdef __cplusplus
}
#endif

