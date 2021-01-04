/*
20120603 : 

20130530 :增加强制udp流淘汰功能，
*/
#include "sapp_api.h"
#include "sapp_private_api.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int udp_stream_table_size;
extern int raw_ip_frag_list_stream_attach(struct streaminfo *stream);
extern int raw_ip_frag_list_stream_detach(struct streaminfo *stream);
extern int set_transport_addr(struct streaminfo *pfstream, UINT16 sport, UINT16 dport);
extern void free_heap_stream_info(struct streaminfo *heap_stream, int layer);
extern void reverse_addr(void *addr, int addrtype);
int copy_ipport_union_addr(struct streaminfo *pstream_heap, struct streaminfo *pstream_stack, int reverse);
extern int guess_if_teredo(const struct streaminfo *pstream, struct mesa_udp_hdr *udphdr);
extern int g_overlay_layer_set[__ADDR_TYPE_MAX][SAPP_SUPPORT_LAYER_NUM_MAX];   

int G_UDP_FLOW_STAT_PROJECT_ID = -1;
int G_UDP_TEREDO_IDENTIFY_PROJECT_ID = -1;

static void udp_change_stream_state(struct streamindex *pindex, struct mesa_udp_hdr *udph, const raw_pkt_t *raw_pkt)
{
	int	ulen =0;
	int	datalen =0;
	struct stream_list *plist=NULL;
	struct streaminfo_private *a_udp_pr = &(pindex->stream);
	struct streaminfo *a_udp=&a_udp_pr->stream_public;
	struct udpdetail_private *pdetail_pr = (struct udpdetail_private *)a_udp->pdetail;
	struct udpdetail *pdetail=(struct udpdetail *)a_udp->pdetail;
	UCHAR threadnum = a_udp->threadnum;
	struct stream_list *udpList_array = G_MESA_GLOBAL_STREAM[threadnum]->udpList;

	ulen = ntohs (udph->uh_ulen);
	datalen =ulen - sizeof (struct mesa_udp_hdr);
	pdetail->lastmtime=(long)g_CurrentTime;
	
	if(a_udp->curdir==DIR_C2S)
	{
		pdetail->serverpktnum++;	
		pdetail->serverbytes+=datalen;
		if(a_udp->dir==DIR_S2C){
			a_udp->dir=DIR_DOUBLE;
		}
		if(G_UDP_FLOW_STAT_PROJECT_ID != -1){
			pdetail_pr->flow_stat->C2S_pkt++;
			pdetail_pr->flow_stat->C2S_byte += datalen;
			pdetail_pr->flow_stat->C2S_all_byte_raw += raw_pkt->raw_pkt_len;
		}
	}	
	else
	{
		pdetail->clientpktnum++;
 		pdetail->clientbytes+=datalen;
		if(a_udp->dir==DIR_C2S){
			a_udp->dir=DIR_DOUBLE;
		}

		if(G_UDP_FLOW_STAT_PROJECT_ID != -1){
			pdetail_pr->flow_stat->S2C_pkt++;
			pdetail_pr->flow_stat->S2C_byte += datalen;
			pdetail_pr->flow_stat->S2C_all_byte_raw += raw_pkt->raw_pkt_len;
		}
			
	}
	pdetail->datalen=datalen;
	pdetail->pdata=(char *)udph + sizeof (struct mesa_udp_hdr);
		
	if(a_udp->stream_state==UDP_ONE_STATE)
    {
	       	if(pdetail->serverpktnum+pdetail->clientpktnum==2)
       		{
       		//remove from oringe stat list
			plist=&(udpList_array[UDP_ONE_STATE]);
			streamleavlist(pindex,plist);

			//add to oringe stat list
			plist=&(udpList_array[UDP_TWO_STATE]);
			a_udp->stream_state=UDP_TWO_STATE;
			streamaddlist(pindex,plist);
			
       		}
	}
	else if(a_udp->stream_state==UDP_TWO_STATE)
	{
		 if(pdetail->serverpktnum+pdetail->clientpktnum>2)
       	{
       		//remove from oringe stat list
			plist=&(udpList_array[UDP_TWO_STATE]);
			streamleavlist(pindex,plist);

			//add to oringe stat list
			plist=&(udpList_array[UDP_MORE_STATE]);
			a_udp->stream_state=UDP_MORE_STATE;
			streamaddlist(pindex,plist);	
       	}
	}
	return;
}

#if SAPP_INSECTICIDE
/* 2017-02-09 临时添加代码, 在线发现莫名其妙BUG, 先判断stream->pfather指针乱的BUG, 也不知道哪把pfather写乱了 */
void iterate_stream_list(const struct streaminfo *stream)
{
	char tmp_buf[8];
	
	while(stream){
		if((ADDR_TYPE_MAC == stream->addr.addrtype) && (stream->pfather != NULL)){
			abort();
		}
		if((stream->addr.addrtype < ADDR_TYPE_IPV4)
		||(stream->addr.addrtype > __ADDR_TYPE_MAX)){
			abort();
		}
		memcpy(tmp_buf, stream->addr.paddr, stream->addr.addrlen<8 ? stream->addr.addrlen:8);
		stream = stream->pfather;
	}
	
}
#endif

#if 1
static struct streamindex *udp_add_new_stream(struct streamindex *pindex,
			struct mesa_udp_hdr *this_udphdr, const raw_pkt_t *raw_pkt)
{
	struct streamindex *pindex_udp=NULL;
	struct udpdetail_private *pdetail_pr=NULL;
	struct udpdetail *pdetail=NULL;
	char createdir;
	struct stream_list *plist=NULL;
	struct streaminfo_private *pstream_udp_pr;
	struct streaminfo *pstream_udp;
	unsigned char threadnum=pindex->stream.stream_public.threadnum;
	
	pindex_udp=malloc_and_copy_streamindex(threadnum, pindex);
#if (0 == USE_RBTREE_INSTEAD_LIST)
	pindex_udp->phashprev = NULL;
#endif	
	pindex_udp->next = NULL;
	pindex_udp->prev = NULL;
	pindex_udp->stream.dirreverse = 0;

	pstream_udp_pr = &pindex_udp->stream;
	pstream_udp = &pstream_udp_pr->stream_public;
		
	createdir=pstream_udp->curdir;
	pstream_udp->dir=createdir;
	pstream_udp->curdir=createdir;

 	pstream_udp->stream_state=UDP_ONE_STATE;

 	copy_ipport_union_addr(pstream_udp, &pindex->stream.stream_public, pstream_udp_pr->layer_dir ^1);
 	
 	pstream_udp->pfather = (struct streaminfo *)copy_stream_info_to_heap((const struct streaminfo_private *)(pindex->stream.stream_public.pfather),  pstream_udp_pr->layer_dir ^1);

#if SAPP_INSECTICIDE
	iterate_stream_list(pstream_udp);
#endif

	/* 2016-07-25 lijia add, 记录当前流最底层隧道类型, 每个流只在创建时做一次即可 */
	get_stream_carry_tunnel_type(pstream_udp, NULL, &pstream_udp_pr->stream_low_layer_tunnel_type);		
	
	if(1 == pstream_udp_pr->layer_dir){
		pstream_udp_pr->stream_dir  = 1;  /* 因为UDP是按DATA建连接, 所以stream_dir肯定和默认规则相同 */
		//((struct streaminfo_private *)(pstream_udp->pfather))->stream_dir = ((struct streaminfo_private *)(pstream_udp->pfather))->layer_dir;	
		//set_stream_addr(pstream_udp, this_udphdr->uh_sport, this_udphdr->uh_dport);
	}else{
		pstream_udp_pr->stream_dir  = 1; /* 因为是UDP按DATA建连接, 所以stream_dir肯定和默认规则相同 */
		//((struct streaminfo_private *)(pstream_udp->pfather))->stream_dir =((struct streaminfo_private *)(pstream_udp->pfather))->layer_dir ^ 1; 	
		//set_stream_addr(pstream_udp, this_udphdr->uh_dport, this_udphdr->uh_sport);
	}

	createdir=pstream_udp->curdir;
	plist=&(G_MESA_GLOBAL_STREAM[threadnum]->udpList[UDP_ONE_STATE]);
	pstream_udp->stream_state=UDP_ONE_STATE;

#if USE_RBTREE_INSTEAD_LIST
	/* note:
		因为插入rbtree时需要和现有其他流做比较, 用以确定插入left还是right分支,
		对于本流来说, layer_dir自身没有意义了, 但要用于和其他流比较地址大小, 
		所以将layer_dir = 1;
	*/
	pstream_udp_pr->layer_dir = 1;
#endif		
	hash_add_stream(pindex_udp);
	streamaddlist(pindex_udp,plist);

	pdetail_pr =  (struct udpdetail_private*)dictator_malloc(threadnum,sizeof(struct udpdetail_private));
	pdetail= &pdetail_pr->udpdetail_public;
	memset(pdetail_pr,0,sizeof(struct udpdetail_private));
	pstream_udp->opstate=OP_STATE_PENDING;
	pstream_udp->pktstate=OP_STATE_PENDING;
	pdetail->createtime=g_CurrentTime;	
	pstream_udp_pr->stream_create_timestamp_ms=sapp_global_val->individual_volatile->current_time_ms;	
	pdetail->lastmtime=g_CurrentTime;
	pstream_udp_pr->timeout=udp_reset_time;

	pstream_udp->pdetail=(void *)pdetail_pr;

	/* 2014-03-26 LiJia add, 某些项目特殊应用初始化, 如标签、原始IP分片列表等 */
	pstream_udp_pr->pproject = project_requirement_create(threadnum);

	/* 2016-07-14 lijia add */
	if(G_UDP_FLOW_STAT_PROJECT_ID != -1){
		pdetail_pr->flow_stat = (struct udp_flow_stat *)dictator_malloc(pstream_udp->threadnum, sizeof(struct udp_flow_stat));
		memset(pdetail_pr->flow_stat, 0, sizeof(struct udp_flow_stat));	
		project_req_add_struct(pstream_udp, G_UDP_FLOW_STAT_PROJECT_ID, pdetail_pr->flow_stat);
	}

	save_polling_inject_context(pstream_udp_pr, raw_pkt);
	if(createdir==DIR_C2S){
		pstream_udp_pr->stream_c2s_route_dir = raw_pkt->route_dir;
	}else{
		pstream_udp_pr->stream_c2s_route_dir = raw_pkt->route_dir ^ 1;
	}
	
	return pindex_udp;
}
#else
static struct streamindex *udp_add_new_stream(struct streamindex *pindex, struct mesa_udp_hdr *udph)
{
	struct streamindex *a_udp=NULL;
	struct udpdetail *pdetail=NULL;
	struct udpdetail_private *pdetail_pr=NULL;
	struct stream_list *plist=NULL;
	char createdir;
	unsigned char threadnum=pindex->stream.stream_public.threadnum;
	struct streaminfo_private *pstream_udp_pr;
	struct streaminfo *pstream_udp;
	
	//a_udp=(struct streamindex *)dictator_malloc(threadnum,sizeof(struct streamindex));
	a_udp=malloc_and_copy_streamindex(threadnum, pindex);
	//memcpy(a_udp,pindex,sizeof(struct streamindex));

	pstream_udp_pr = &a_udp->stream;
	pstream_udp = &pstream_udp_pr->stream_public;

	copy_ipport_union_addr(pstream_udp, &pindex->stream.stream_public, 0);

	pstream_udp->pfather = (struct streaminfo *)copy_stream_info_to_heap((struct streaminfo_private *)pstream_udp->pfather, 0);
	//set_stream_addr(a_udp->stream.pfather, udph->uh_sport, udph->uh_dport, &a_udp->stream.addr);
	set_transport_addr(pstream_udp, udph->uh_sport, udph->uh_dport);

	createdir=pstream_udp->curdir;
	plist=&(G_MESA_GLOBAL_STREAM[threadnum]->udpList[UDP_ONE_STATE]);
	pstream_udp->stream_state=UDP_ONE_STATE;

	hash_add_stream(a_udp);	
	streamaddlist(a_udp,plist);
	pdetail_pr = (struct udpdetail_private*)dictator_malloc(threadnum,sizeof(struct udpdetail_private)); 
	memset(pdetail_pr,0,sizeof(struct udpdetail_private));
	pdetail=&pdetail_pr->udpdetail_public;
	pstream_udp->opstate=OP_STATE_PENDING;
	pstream_udp->pktstate=OP_STATE_PENDING;
	pdetail->createtime=g_CurrentTime;
	pstream_udp->pdetail=(void *)pdetail_pr;

	pstream_udp->curdir=createdir;
	pstream_udp->dir=createdir;

	pstream_udp_pr->pproject = project_requirement_create(pstream_udp->threadnum);
	
	return a_udp;	
}
#endif

static inline void udp_cleardata(struct streaminfo *a_udp)
{
	struct udpdetail *pdetail=(struct udpdetail *)a_udp->pdetail;

   	pdetail->datalen=0;
	pdetail->pdata=NULL;

	return;
}

void udp_free_stream(struct streamindex *pindex)
{	
	struct stream_list *plist=NULL;
	struct streaminfo_private *pstream_pr=&(pindex->stream);
	struct streaminfo *pstream=&(pstream_pr->stream_public);	
	struct udpdetail_private *pdetail_pr=(struct udpdetail_private *)(pstream->pdetail);
	UCHAR threadnum = pstream->threadnum;

	pstream_pr->raw_pkt = NULL; /* 2015-02-04 lijia add, 不能因此调用而触发MESA_kill_xxx */

	if(pdetail_pr->apme!=NULL)
	{
		pstream->opstate=OP_STATE_CLOSE;
		//udp stream 回调
		pstream->pktstate=OP_STATE_CLOSE; // add by lijia 20141202
		stream_process_udp(pstream,NULL,NULL,NULL,&(pdetail_pr->apme),&(pstream->opstate));  
		udp_cleardata(pstream);
		
	}
	plist=&(G_MESA_GLOBAL_STREAM[threadnum]->udpList[pstream->stream_state]);
	streamleavlist(pindex, plist);
	hash_del_stream(pindex);
	
	if(pstream->pdetail!=NULL)
		dictator_free(threadnum,pstream->pdetail);

	project_requirement_destroy(threadnum, pstream_pr->pproject);
	pstream_pr->pproject = NULL;

	if(pstream_pr->timeout > udp_reset_time){ /* 链接独有超时时间, 减少计数 */
		sapp_global_mthread[threadnum].udp_stream_special_timeout_num--;
	}

	if(udp_stream_table_size > 0){
		free_heap_stream_info(pstream, 0);
	}

	free_polling_inject_context(pstream_pr);
	
	free_streamindex(threadnum,pindex);
}

//add by lqy 20130530
// 根据设定的时间强制淘汰复用的四元组信息
// return 1 进行了重置，0 未进行重置
static int udp_reset_stream_bytime(struct streamindex *pindex)
{
	struct stream_list *plist;
	struct streaminfo_private *pstream_pr;
	struct streaminfo *pstream;
	struct udpdetail_private *pdetail_pr;
	struct udpdetail *pdetail;
	UCHAR threadnum;
	
	pstream_pr=&(pindex->stream);
	if(0 == pstream_pr->timeout){ /* 没设置超时时间, 不能按时间重置 */
		return 0;
	}
	
	pstream=&(pstream_pr->stream_public);
	pdetail_pr=(struct udpdetail_private *)(pstream->pdetail);
	pdetail=(struct udpdetail *)pstream->pdetail;
	threadnum = pstream->threadnum;

	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[threadnum]->sys_stat;
	
	if((UINT16)((UINT64)g_CurrentTime-pdetail->lastmtime) > pstream_pr->timeout)
	{
		//清理以前的调用信息
		plist=&(G_MESA_GLOBAL_STREAM[threadnum]->udpList[pstream->stream_state]);
		streamleavlist(pindex, plist);
//		pstream->stream.opstate=OP_STATE_CLOSE;
		pstream->opstate=OP_STATE_CLOSE;
		pstream->pktstate=OP_STATE_CLOSE;  // add by lijia 20141202

		pstream_pr->stream_close_reason = STREAM_CLOSE_REASON_TIMEOUT;
		
		stream_process_udp(pstream,NULL,NULL,NULL,&(pdetail_pr->apme),&(pstream->opstate));  

		project_requirement_destroy(threadnum, pstream_pr->pproject);
		pstream_pr->pproject = project_requirement_create(threadnum);

		/* 2015-12-28 lijia add, 流重置, 从新申请内存 */
		if(G_UDP_FLOW_STAT_PROJECT_ID != -1){
			pdetail_pr->flow_stat = (struct udp_flow_stat *)dictator_malloc(threadnum, sizeof(struct udp_flow_stat));
			memset(pdetail_pr->flow_stat, 0, sizeof(struct udp_flow_stat));	
			project_req_add_struct(pstream, G_UDP_FLOW_STAT_PROJECT_ID, pdetail_pr->flow_stat);
		}
		
		//重置所有状态
	    memset(pdetail,0,sizeof(struct udpdetail ));
//		pstream->stream.opstate=OP_STATE_PENDING;
		pstream->opstate=OP_STATE_PENDING;
		pstream->pktstate=OP_STATE_PENDING;

		pdetail->createtime=g_CurrentTime;
		pstream_pr->stream_create_timestamp_ms=sapp_global_val->individual_volatile->current_time_ms;	
		plist=&(G_MESA_GLOBAL_STREAM[threadnum]->udpList[UDP_ONE_STATE]);
		pstream->stream_state=UDP_ONE_STATE;
//		streamaddlist(pstream,plist);
		streamaddlist(pindex,plist);

		local_sys_stat->count[SAPP_STAT_UDP_STREAM_RESET]++;
		return 1;
	}
	return 0;
}


#if 0
static inline int set_port_20141216(struct streaminfo *pfstream, const struct mesa_udp_hdr *this_udphdr)
{
	if(ADDR_TYPE_IPV4 == pfstream->addr.addrtype || __ADDR_TYPE_IP_PAIR_V4 == pfstream->addr.addrtype){
		struct stream_tuple4_v4 *tuple4_v4 = (struct stream_tuple4_v4 *)pfstream->addr.paddr;
		tuple4_v4->source = this_udphdr->uh_sport;
		tuple4_v4->dest = this_udphdr->uh_dport;
		pfstream->addr.addrtype = ADDR_TYPE_IPV4;
	}else{
		struct stream_tuple4_v6 *tuple4_v6 = (struct stream_tuple4_v6 *)pfstream->addr.paddr;
		tuple4_v6->source = this_udphdr->uh_sport;
		tuple4_v6->dest = this_udphdr->uh_dport;
		pfstream->addr.addrtype = ADDR_TYPE_IPV6;
	}

	return 0;
}
#endif

static int set_addr_recur(struct streaminfo *this_stream, int reverse)
{
	if(NULL == this_stream){
		return 0;
	}

	reverse_addr(this_stream->addr.paddr, this_stream->addr.addrtype);

	return set_addr_recur(this_stream->pfather, reverse);
}


int dealipv4udppkt(struct streamindex *pindex, const struct mesa_ip4_hdr * this_iphdr,
		int thread_num,unsigned char routedir, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr)
{
	struct mesa_udp_hdr *udph;
	int datalen, iplen,ulen;
	//struct streamindex tmp_index;
	//struct streamindex *ptmp=&tmp_index;
	struct streamindex *a_index=NULL;
	struct udpdetail *pdetail=NULL;
	struct udpdetail_private *pdetail_pr=NULL;
	struct streaminfo_private *pstream_pr=&(pindex->stream);
	struct streaminfo *pstream=&(pstream_pr->stream_public);
#if (COMPAT_PAPP_FOR_BENCHMARK == 0)	
	struct streaminfo_private *stack_stream_pr = &(pindex->stream); /* 2016-11-24 lijia add, 如果是l2tp, teredo隧道, 使用栈里的指针 */
#endif	
	int next_layer_offset;
	void *tmpme=NULL;	
	int hlen=0;
	int ret=PASS;
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[thread_num]->sys_stat;
	int try_to_update_addr_info = 0;

	iplen = ntohs (this_iphdr->ip_len);
	hlen=4 * this_iphdr->ip_hl;
	next_layer_offset = offset_to_raw_pkt_hdr + sizeof(struct mesa_udp_hdr);

	udph = (struct mesa_udp_hdr *) ((char*)this_iphdr +hlen );
	ulen = ntohs (udph->uh_ulen);
	/* 2015-12-29 lijia modify, 某些UDP包没有负载数据, 没有意义, 直接丢弃 */
	if(unlikely(iplen - hlen < ulen || ulen <= (int)sizeof (struct mesa_udp_hdr))){
			return PASS;
	}
	datalen =ulen - sizeof (struct mesa_udp_hdr);

	pstream_pr->offset_to_ip_hdr = (char *)udph - (char *)this_iphdr;
	pstream_pr->raw_pkt = raw_pkt; /* 2014-12-30 lijia add */
	//set_stream_addr(pfstream, udph->uh_sport, udph->uh_dport, &ptmp->stream.addr);
	//pstream->pfather=&pfstream->stream_public;
	pstream->type=STREAM_TYPE_UDP;
	pstream->routedir=routedir;
	pstream->threadnum=thread_num;

	local_sys_stat->count[SAPP_STAT_RCV_UDP]++;
	local_sys_stat->length[SAPP_STAT_RCV_UDP]+=ulen;
	if (routedir == sapp_global_val->config.packet_io.inbound_route_dir)
	{
		local_sys_stat->count[SAPP_STAT_UDP_INBOUND]++;
		local_sys_stat->length[SAPP_STAT_UDP_INBOUND] += ulen;
	}
	else
	{
		local_sys_stat->count[SAPP_STAT_UDP_OUTBOUND]++;
		local_sys_stat->length[SAPP_STAT_UDP_OUTBOUND] += ulen;
	}

	//add by lqy 20130530 
	// udp有不开启流还原的功能需求，直接按单包单流处理
	if(unlikely(0 ==udp_stream_table_size))
	{
		struct udpdetail_private pdetail_pr;
		memset(&pdetail_pr, 0, sizeof(struct udpdetail_private));
		pdetail = (struct udpdetail *)&pdetail_pr;
	
		set_transport_addr(pstream, udph->uh_sport, udph->uh_dport);

		pstream_pr->offset_to_ip_hdr = (char *)udph - (char *)this_iphdr;
		
		/* 单包级, 假定源端口大的为Client */
		//if(memcmp(&udph->uh_sport, &udph->uh_dport, sizeof(short)) >= 0){
		if(ntohs(udph->uh_sport) >= ntohs(udph->uh_dport)){
			pstream->curdir=DIR_C2S;
			pstream_pr->layer_dir = 1;
			//set_stream_addr(pfstream, udph->uh_sport, udph->uh_dport, &ptmp->stream);
		}
		else
		{
			pstream->curdir=DIR_S2C;
			pstream_pr->layer_dir = 0;
			//set_stream_addr(pfstream, udph->uh_dport, udph->uh_sport, &ptmp->stream);
			set_addr_recur(pstream, 1);
		}

		pdetail->createtime = g_CurrentTime;
		pstream_pr->stream_create_timestamp_ms=sapp_global_val->individual_volatile->current_time_ms;	
		pdetail->datalen = datalen;
		pdetail->pdata = (char *)udph + sizeof (struct udphdr);
		pstream->pdetail=(void *)pdetail;

		pstream_pr->pproject = project_requirement_create(thread_num);

		if(G_UDP_FLOW_STAT_PROJECT_ID != -1){
			pdetail_pr.flow_stat = (struct udp_flow_stat *)dictator_malloc(thread_num, sizeof(struct udp_flow_stat));
			memset(pdetail_pr.flow_stat, 0, sizeof(struct udp_flow_stat));	
			project_req_add_struct(pstream, G_UDP_FLOW_STAT_PROJECT_ID, pdetail_pr.flow_stat);
		}
		
		ret=stream_process_udp(pstream, (const void *)this_iphdr, (const void *)udph, raw_pkt,&tmpme,&(pstream->opstate));  
		project_requirement_destroy(thread_num, pstream_pr->pproject);
		pstream_pr->pproject = NULL;
	}
	else	
	{
		set_transport_addr(pstream, udph->uh_sport, udph->uh_dport);

		a_index =(struct streamindex * ) findstreamindex (pindex, raw_pkt);
		if (unlikely(!a_index)){
			//a_index = udp_add_new_stream (ptmp, udph);
			a_index = udp_add_new_stream(pindex, udph, raw_pkt);
		}
		//add by lqy 只有当链接未重置时进行lru
		else if(udp_reset_stream_bytime(a_index)==0)
		{
			lrustream(a_index);
		}	

		/* 2014-11-15 lijia add, for udp serial kill udp */
		if(unlikely(a_index->stream.stream_killed_flag != 0)){
			return DROP;
		}

		/* NOTE: 更新pstream指针, 指向堆中存储的内存 */
		pstream_pr=&(a_index->stream);
		pstream=&(pstream_pr->stream_public);		
		//pstream->addr.pktipfragtype = pstream->stream_public.addr.pktipfragtype; /* 2015-11-04 lijia add, IP分片类型更新 */
		pdetail_pr=(struct udpdetail_private *)(pstream->pdetail);
		
		if(unlikely(pdetail_pr->drop_stream_flag != 0)){ /* 2020-06-02 lijia add */
			return DROP;
		}

		if(pstream->curdir==DIR_S2C){
			if(pdetail_pr->udpdetail_public.clientpktnum == 0){ /* 当前方向的第一个包, 尝试更新底层隧道的单向地址信息(如MPLS, GTP) */
				try_to_update_addr_info = 1;
			}
		}else{
			if(pdetail_pr->udpdetail_public.serverpktnum == 0){ /* 当前方向的第一个包, 尝试更新底层隧道的单向地址信息(如MPLS, GTP) */
				try_to_update_addr_info = 1;
			}
		}
		if(try_to_update_addr_info == 1){
			update_opposite_addr_info((struct streaminfo_private *)(pstream->pfather),
					(struct streaminfo_private *)(pindex->stream.stream_public.pfather), pstream->curdir);
		}
		
		update_polling_inject_context(pstream_pr, raw_pkt);
		
		udp_change_stream_state(a_index,udph, raw_pkt);

		pstream_pr->offset_to_ip_hdr = (char *)udph - (char *)this_iphdr;
		pstream_pr->raw_pkt = raw_pkt; /* 2014-12-30 lijia add */

		if(sapp_is_overlay_layer(pstream_pr, raw_pkt) != 0){
			ret = stream_process_overlay_udp(pstream,(const void *)this_iphdr, (const void *)udph, raw_pkt,&(pdetail_pr->apme),&(pstream->opstate));
			if(DROP == ret){
				return DROP;
			}
			ret = vxlan_entry(stack_stream_pr, (char *)udph+sizeof(struct mesa_udp_hdr), thread_num, routedir, raw_pkt, next_layer_offset);
			udp_cleardata(pstream);
			/* overlay UDP层不再继续后续的隧道检测 */
			return ret;
		}else{		
			ret=stream_process_udp(pstream,(const void *)this_iphdr, (const void *)udph, raw_pkt,&(pdetail_pr->apme),&(pstream->opstate)); 
			udp_cleardata(pstream);
		}
     }
     
#if (COMPAT_PAPP_FOR_BENCHMARK == 0)
	if(unlikely(DROP == ret)){ /* 插件返回DROP不再进行后续处理 */
		return DROP;
	}
	
	if(pstream_pr->stream_carry_up_layer_tunnel_type & STREAM_TUNNLE_TEREDO){
		ret = teredo_entry(stack_stream_pr, udph, thread_num, routedir, raw_pkt, next_layer_offset);		
	}
	
	if(pstream_pr->stream_carry_up_layer_tunnel_type & STREAM_TUNNLE_L2TP){
		ret = l2tpv2_entry(stack_stream_pr, udph, thread_num, routedir, raw_pkt, next_layer_offset);	
	}
	if(pstream_pr->stream_carry_up_layer_tunnel_type & STREAM_TUNNEL_GPRS_TUNNEL){
		ret = gtp_entry(stack_stream_pr, udph, thread_num, routedir, raw_pkt, next_layer_offset);
	}

#endif

	if(DROP == ret){
		sapp_runtime_log(RLOG_LV_DEBUG, "UDP stream: %s, curdir:%d, return DROP.", printaddr(&pstream->addr, pstream->threadnum), pstream->curdir);
	}

	return ret;
}

int dealipv6udppkt(struct streamindex *pindex,const struct mesa_ip6_hdr *a_packet,
	char *data, int thread_num,unsigned char routedir, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr)
{
	struct mesa_udp_hdr *udph = (struct mesa_udp_hdr *)data;
	int ulen, iplen;
	struct streamindex *a_index=NULL;
	struct streaminfo_private *pstream_pr=&(pindex->stream);
	struct streaminfo *pstream=&(pstream_pr->stream_public);	
	struct udpdetail_private *pdetail_pr=NULL;
	void *tmpme=NULL;
	int ret=PASS;
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[thread_num]->sys_stat;
	int try_to_update_addr_info = 0;

	iplen = ntohs (a_packet->ip6_payload_len);
	ulen = ntohs (udph->uh_ulen);
	
	if(unlikely(iplen < ulen || ulen <= (int)sizeof (struct mesa_udp_hdr))){
		return PASS;
	}		

	local_sys_stat->count[SAPP_STAT_RCV_UDP]++;
	local_sys_stat->length[SAPP_STAT_RCV_UDP]+=ulen;
	if (routedir == sapp_global_val->config.packet_io.inbound_route_dir)
	{
		local_sys_stat->count[SAPP_STAT_UDP_INBOUND]++;
		local_sys_stat->length[SAPP_STAT_UDP_INBOUND] += ulen;
	}
	else
	{
		local_sys_stat->count[SAPP_STAT_UDP_OUTBOUND]++;
		local_sys_stat->length[SAPP_STAT_UDP_OUTBOUND] += ulen;
	}

	pstream->addr.addrlen=sizeof(struct layer_addr_udp);
	pstream_pr->addr_use_as_hash = 0;
	//ptmp->stream.p_layer_header = udph;
/* IP, UDP层合并后, 不再更新UDP层的offset_to_raw_pkt_hdr */
#if 0
	pstream_pr->offset_to_raw_pkt_hdr = offset_to_raw_pkt_hdr;
#endif
	pstream_pr->offset_to_ip_hdr = (char *)udph - (char *)a_packet;
	
	pstream_pr->raw_pkt = raw_pkt; /* 2014-12-30 lijia add */
	
	//pstream->pfather=pfstream;
	pstream->type=STREAM_TYPE_UDP;
	pstream->routedir=routedir;
	pstream->threadnum=thread_num;

	//add by lqy 20130530 
	// udp有不开启流还原的功能需求，直接按单包单流处理
	
	if(unlikely(0 == udp_stream_table_size))
	{
		/* 单包级, 假定源端口大的为Client */
		if(memcmp(&udph->uh_sport, &udph->uh_dport, sizeof(short)) >= 0){
			pstream->curdir=DIR_C2S;
			pstream_pr->layer_dir = 1;
		}
		else
		{
			pstream->curdir=DIR_S2C;
			pstream_pr->layer_dir = 0;
		}

		pstream_pr->offset_to_ip_hdr = (char *)udph - (char *)a_packet;
	
		pstream_pr->pproject = project_requirement_create(thread_num);

		if(G_UDP_FLOW_STAT_PROJECT_ID != -1){
			pdetail_pr->flow_stat = (struct udp_flow_stat *)dictator_malloc(thread_num, sizeof(struct udp_flow_stat));
			memset(pdetail_pr->flow_stat, 0, sizeof(struct udp_flow_stat));	
			project_req_add_struct(pstream, G_UDP_FLOW_STAT_PROJECT_ID, pdetail_pr->flow_stat);
		}
		
		ret=stream_process_udp(pstream, (const void *)a_packet, (const void *)udph, raw_pkt,&tmpme, &pstream->opstate);  
		project_requirement_destroy(thread_num, pstream_pr->pproject);
		pstream_pr->pproject = NULL;
	}
	else	
	{
		if(ntohs(udph->uh_sport) > ntohs(udph->uh_dport)){
			pstream_pr->layer_dir = 1;
			pstream->curdir = DIR_C2S;
		}else{
			 if(unlikely(udph->uh_sport == udph->uh_dport)){ /* 如果端口恰好完全相同, 需要比较IP地址 */
			 	if(memcmp(&a_packet->ip6_src, &a_packet->ip6_dst, sizeof(struct in6_addr)) >= 0){
					pstream_pr->layer_dir = 1;
					pstream->curdir = DIR_C2S;
			 	}else{
					pstream_pr->layer_dir = 0;
					pstream->curdir = DIR_S2C;
			 	}
			 }else{		
				pstream_pr->layer_dir = 0;
				pstream->curdir = DIR_S2C;
			}
		}

		//set_port_20141216(pfstream, udph);
		set_transport_addr(pstream, udph->uh_sport, udph->uh_dport);		
	
		a_index =(struct streamindex * ) findstreamindex (pindex, raw_pkt);
		if(unlikely(!a_index)){
			a_index = udp_add_new_stream(pindex, udph, raw_pkt);
		}
		//add by lqy 只有当链接未重置时进行lru
		else if( udp_reset_stream_bytime(a_index)==0)
		{
			lrustream(a_index);			
		}	
		
		/* 2014-11-15 lijia add, for udp serial kill udp */
		if(unlikely(a_index->stream.stream_killed_flag != 0)){
			return DROP;
		}

		/* NOTE: 更新pstream指针, 指向堆中存储的内存 */
		pstream_pr=&(a_index->stream);
		pstream=&(pstream_pr->stream_public);		
		pdetail_pr=(struct udpdetail_private *)(pstream->pdetail);

		if(pstream->curdir==DIR_S2C){
			if(pdetail_pr->udpdetail_public.clientpktnum == 0){ /* 当前方向的第一个包, 尝试更新底层隧道的单向地址信息(如MPLS, GTP) */
				try_to_update_addr_info = 1;
			}
		}else{
			if(pdetail_pr->udpdetail_public.serverpktnum == 0){ /* 当前方向的第一个包, 尝试更新底层隧道的单向地址信息(如MPLS, GTP) */
				try_to_update_addr_info = 1;
			}
		}
		if(try_to_update_addr_info == 1){
			update_opposite_addr_info((struct streaminfo_private *)(pstream->pfather),
					(struct streaminfo_private *)(pindex->stream.stream_public.pfather), pstream->curdir);
		}
		
		udp_change_stream_state(a_index,udph, raw_pkt);

		/* 更新pstream指针 */
		pstream_pr=&(a_index->stream);
		pstream=&(pstream_pr->stream_public);

		update_polling_inject_context(pstream_pr, raw_pkt);

/* IP, UDP层合并后, 不再更新UDP层的offset_to_raw_pkt_hdr */
#if 0
		pstream_pr->offset_to_raw_pkt_hdr = offset_to_raw_pkt_hdr;
#endif		
		pstream_pr->offset_to_ip_hdr = (char *)udph - (char *)a_packet;
		pstream_pr->raw_pkt = raw_pkt; /* 2014-12-30 lijia add */
		pdetail_pr=(struct udpdetail_private *)(pstream->pdetail);
		ret=stream_process_udp(pstream,(const void *)a_packet, (const void *)udph, raw_pkt,&(pdetail_pr->apme),&(pstream->opstate));  
		udp_cleardata(pstream);
	}

	/* TODO 2, 基于IPv6的UDP port 1701 L2TP协议 */

	if(DROP == ret){
		sapp_runtime_log(RLOG_LV_DEBUG, "UDP stream: %s, curdir:%d, return DROP.", printaddr(&pstream->addr, pstream->threadnum), pstream->curdir);
	}
	
	return ret;
}

/* lijia comment: a_packet可能是真实原始包, 也可能是malloc的IP重组包, 靠addr.pkttype区分 */
int process_ipv4_pkt (struct streamindex *pfindex,const struct mesa_ip4_hdr * a_packet,int thread_num,
						unsigned char routedir, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr)
{
     int ret=PASS;
     void *next_layer_hdr;
     int next_layer_offest;
     struct streaminfo_private *pfstream_pr = &(pfindex->stream); 
     sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[thread_num]->sys_stat;

	ret=stream_process_ipv4(&(pfstream_pr->stream_public),(const struct ip *)a_packet,thread_num,routedir, raw_pkt);
	if(unlikely(ret==DROP)){
		return DROP;
	}	

	next_layer_hdr = ((char *)a_packet + (a_packet->ip_hl << 2));
	next_layer_offest = offset_to_raw_pkt_hdr + (a_packet->ip_hl << 2);

	switch (a_packet->ip_p)
	{
		case IPPROTO_TCP:
			((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offest;
			//ret=dealipv4tcppkt(pfstream_pr,a_packet,thread_num,routedir,raw_pkt, next_layer_offest);
			ret=dealipv4tcppkt(pfindex,a_packet,thread_num,routedir,raw_pkt, next_layer_offest);
		break;

		case IPPROTO_UDP:
			((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offest;
			ret=dealipv4udppkt(pfindex,a_packet,thread_num,routedir,raw_pkt, next_layer_offest);
		break;

		case IPPROTO_IPV6:
#if COMPAT_PAPP_FOR_BENCHMARK
		return PASS;
#endif
		{
			((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offest;
			//void *next_layer_hdr = (char *)a_packet + a_packet->ip_hl*4;
			ret = ipv6_entry(pfstream_pr,next_layer_hdr,thread_num,routedir, raw_pkt, next_layer_offest);
			local_sys_stat->count[SAPP_STAT_TUNNEL_6OVER4]++;
			local_sys_stat->length[SAPP_STAT_TUNNEL_6OVER4]+= ntohs(a_packet->ip_len);
		}	
		break;

		case IPPROTO_GRE:
#if COMPAT_PAPP_FOR_BENCHMARK
		return PASS;
#endif		
			((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offest;
			ret = gre_entry(pfstream_pr,next_layer_hdr,thread_num,routedir, raw_pkt, next_layer_offest);
		break;

		case IPPROTO_IPIP:
#if COMPAT_PAPP_FOR_BENCHMARK
		return PASS;
#endif		
			((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offest;
			ret = ipv4_entry(pfstream_pr,next_layer_hdr,thread_num,routedir, raw_pkt, next_layer_offest);
			local_sys_stat->count[SAPP_STAT_TUNNEL_IPIP]++;
			local_sys_stat->length[SAPP_STAT_TUNNEL_IPIP]+= ntohs(a_packet->ip_len);			
		break;

		case IPPROTO_ICMP:
#if 0 /* 2017-05-19 lijia modify, GDEV保活转到g_device_plug插件中实现, 平台内部不再处理 */		
			((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offest;
			ret = icmp_entry(pfstream_pr,next_layer_hdr,thread_num,routedir,raw_pkt, next_layer_offest);
#endif			
		break;

		case IPPROTO_L2TPV3:
			sapp_runtime_log(RLOG_LV_INFO, "recv ipv4 carry L2TPv3, not support yet!\n");
			ret = PASS;
		break;

		case IPPROTO_ESP:
			sapp_runtime_log(RLOG_LV_INFO, "ipv4_layer recv IPPROTO_ESP, not support yet!\n");
			ret = PASS;
		break;
		
		case IPPROTO_SCTP:
			sapp_runtime_log(RLOG_LV_INFO, "ipv4_layer recv IPPROTO_SCTP, not support yet!\n");
			ret = PASS;
		break;

		case IPPROTO_IGMP:
			sapp_runtime_log(RLOG_LV_INFO, "ipv4_layer recv IPPROTO_IGMP, not support yet!\n");
			ret = PASS;		
		break;

		default:	
			/* unknown protocol */	
			local_sys_stat->count[SAPP_STAT_RCV_UNKNOWN]++;
			local_sys_stat->length[SAPP_STAT_RCV_UNKNOWN]+= raw_pkt->raw_pkt_len;		
			sapp_runtime_log(RLOG_LV_INFO, "unsupport Ipv4 protocol:%u, pkt seq:%llu\n", a_packet->ip_p,local_sys_stat->count[SAPP_STAT_RCV_RAW]);
		break;
	}
	
	return ret; 
}


char udp_teredo_identify_entry(const struct streaminfo *pstream, const void *this_hdr, const void *raw_pkt, void **pme)
{
	if(-1 == G_UDP_TEREDO_IDENTIFY_PROJECT_ID){
		sapp_runtime_log(RLOG_LV_FATAL, "plug udp_teredo_identify: project_register error!\n");
		return APP_STATE_DROPME;
	}	

	if(guess_if_teredo(pstream, (struct mesa_udp_hdr *)this_hdr) != 0){
		struct streaminfo_private *pstream_pr = (struct streaminfo_private *)pstream;
		pstream_pr->stream_carry_up_layer_tunnel_type |= STREAM_TUNNLE_TEREDO;		
	}

	return APP_STATE_DROPME; /* 每个流只看第一个包, 不管是否teredo隧道, 后续都不再处理了 */
}


#ifdef __cplusplus
}
#endif

