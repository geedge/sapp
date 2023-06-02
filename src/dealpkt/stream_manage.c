
/*
*********************************************
1. 20130803 刘庆云
1)   原来的流表的hash链表是无序的挂在同一key值上；
      修改为按照四元组的大小排序后放在hash表的同一个链表上；
2) 通过在   findandsethashindex 查找时预设要插入的上下链表，减少插入时的重新查表


2 . adjust by lqy 20130917 streamaddlist
1) 发生了淘汰之后需要重新计算要插入的位置
2) 每次淘汰的链接数目为总链接数目的2%

3 . adjust by lqy 20140810 
1) 发生淘汰时，最大不超过100个

4. adjust by lqy 20141203 
1)lru时检测链表最后一个是否超时，超时即刻淘汰

5.adjust by lqy 20141212
1)为每个流增加全局唯一索引stream_index 可以通过函数获得
2)是否支持全包接口由开关设定
3)每个链接均进行lru
4) fix hash冲突时排序的链表错误
*/
#include "sapp_api.h"
#include "sapp_private_api.h"
#include "sapp_declaration.h"
#include "stream_inc/stream_base.h"
#include "timeout.h"

#ifdef __cplusplus
extern "C" {
#endif

int sapp_version_v4_20191119;

/* 
	下面的版本号用于packet_io_lib校验, 防止平台和dl.so不匹配导致运行异常, 或已修复的BUG未更新.
*/
#if IOMODE_PCAP
int sapp_packet_io_v = 20210907;
#elif IOMODE_PAG
int sapp_packet_io_v = 20151106;
#elif IOMODE_PFRING
int sapp_packet_io_v = 20160505;
#elif IOMODE_DPDK
int sapp_packet_io_v = 20160929;
#elif IOMODE_IPFILE
int sapp_packet_io_v = 20160426;
#elif IOMODE_TOPSEC
int sapp_packet_io_v = 20151014;
#elif IOMODE_MARSIO
int sapp_packet_io_v = 20190820;
#elif IOMODE_SMITH
int sapp_packet_io_v = 20161027;
#elif IOMODE_DPDK_VXLAN
int sapp_packet_io_v = 20161101;
#elif IOMODE_PAG_MARSIO
int sapp_packet_io_v = 20170407;
#endif

#define MAX_DEFALUT_TIMEOUT_S 86400

#define STREAM_ONCE_DEL_NUM 1000
void packet_io_status_stream_hash_update(int thread_seq, unsigned long hash_list_num);
void packet_io_status_stream_update(int tid, UCHAR stream_type, UCHAR stream_state,  int action);
static inline void update_stream_status(UCHAR threadnum, UCHAR type, UCHAR stream_state,  int action);
int project_requirement_global_init(void);
static inline void __do_streamleavlist(struct streamindex *pindex,struct stream_list *plist);

int tcp_stream_table_size=0;
int udp_stream_table_size=0;
int tcpstate_num[MAX_TCP_STATE]={8000,2000,4000};
int udpstate_num[MAX_UDP_STATE]={2000,2000,2000};
int tcp_flood_detect_model=TCP_FLOOD_DETECT_OFF;
int tcp_support_all=TCP_SUPPORT_ENTRYALL_ON;
int tcp_dataflood_pktlen=5;
struct global_stream **G_MESA_GLOBAL_STREAM;

extern int g_overlay_layer_set[__ADDR_TYPE_MAX][SAPP_SUPPORT_LAYER_NUM_MAX];

static int init_stream_detail(struct global_stream *g_stream)
{
	int i = 0;
	memset(g_stream, 0, sizeof(struct global_stream));
	g_stream->user_define_timer = timeouts_open(0, &g_stream->timer_error);
	for (i = 0; i < MAX_TCP_STATE; i++)
	{
		g_stream->tcpList[i].max_cnt = tcpstate_num[i];
		g_stream->tcpList[i].cnt = 0;
		g_stream->tcpList[i].streamindex_timer = timeouts_open(0, &g_stream->tcpList[i].timer_error);
	}
	for (i = 0; i < MAX_UDP_STATE; i++)
	{
		g_stream->udpList[i].max_cnt = udpstate_num[i];
		g_stream->udpList[i].cnt = 0;
		g_stream->udpList[i].streamindex_timer = timeouts_open(0, &g_stream->udpList[i].timer_error);
	}


	//预先分配hash指针
	g_stream->tcp_stream_table = (struct streamindex **)sapp_mem_malloc(SAPP_MEM_FIX_GLOBAL_STREAM, -1, tcp_stream_table_size * sizeof(char *));
	memset(g_stream->tcp_stream_table, 0, tcp_stream_table_size * sizeof(char *));
	g_stream->udp_stream_table = (struct streamindex **)sapp_mem_malloc(SAPP_MEM_FIX_GLOBAL_STREAM, -1, udp_stream_table_size * sizeof(char *));
	memset(g_stream->udp_stream_table, 0, udp_stream_table_size * sizeof(char *));
	//记录hash的状态
	g_stream->tcp_stream_talbe_hash_count = (unsigned short *)sapp_mem_malloc(SAPP_MEM_FIX_GLOBAL_STREAM, -1, tcp_stream_table_size * sizeof(short));
	memset(g_stream->tcp_stream_talbe_hash_count, 0, tcp_stream_table_size * sizeof(short));
	g_stream->udp_stream_talbe_hash_count = (unsigned short *)sapp_mem_malloc(SAPP_MEM_FIX_GLOBAL_STREAM, -1, udp_stream_table_size * sizeof(short));
	memset(g_stream->udp_stream_talbe_hash_count, 0, udp_stream_table_size * sizeof(short));

	int max_cnt = tcp_stream_table_size + udp_stream_table_size;

	//预先分配stream_index池
	STAILQ_INIT(&g_stream->freeList);
	g_stream->__freeList_real_head = (struct stream_index_list_item *)sapp_mem_malloc(SAPP_MEM_FIX_GLOBAL_STREAM, -1, (max_cnt) * sizeof(struct stream_index_list_item));
	memset(g_stream->__freeList_real_head, 0, (max_cnt) * sizeof(struct stream_index_list_item));
	for(i = 0; i < max_cnt; i++)
	{
		g_stream->__freeList_real_head[i].index.stream.stream_public.stream_index=i;	
		STAILQ_INSERT_TAIL(&g_stream->freeList, g_stream->__freeList_real_head+i, entries);
	}
	g_stream->__freeList_real_head[max_cnt -1].index.stream.stream_public.stream_index=max_cnt -1;	

	g_stream->freeList_max_cnt = max_cnt;
	g_stream->freeList_cnt = max_cnt;
	return 0;
}

int tcp_set_flood_detect_model(int model)
{
	tcp_flood_detect_model=model;
	return 0;
}

int tcp_set_creatlink_model(int model)
{
	tcp_creatlink_model=model;
	return 0;
}
//设置是否开启tcpall模式
int tcp_set_support_tcpall_model(int model)
{
	tcp_support_all=model;
	return 0;
}
int tcp_set_default_unorder_num(unsigned short max_unorder)
{
	tcp_default_unorder=max_unorder;
	return 0;
}

int tcp_set_max_unorder(int max_unorder) //2014-12-25 lijia add, 兼容旧平台, xj_fd
{
	tcp_default_unorder=max_unorder;
	return 0;
}

int tcp_set_stream_num(int tcpsyn,int tcpdata,int tcpnouse)
{
	
	tcpstate_num[TCP_SYN_STATE]=tcpsyn;
	tcpstate_num[TCP_DATA_STATE]=tcpdata;
	tcpstate_num[TCP_NOUSE_STATE]=tcpnouse;
	return 0;
}
void stream_set_default_nopkt_time(unsigned short timeout)
{
	link_default_nopkt_time=timeout;
}

static inline UINT64 stream_get_detail_last_mtime(const struct streamindex *pindex)
{
	UINT64 last_mtime;
	
	if(STREAM_TYPE_TCP == pindex->stream.stream_public.type){
		last_mtime = pindex->stream.stream_public.ptcpdetail->lastmtime;
	}else{
		last_mtime = pindex->stream.stream_public.pudpdetail->lastmtime;
	}

	return last_mtime;
}

static void stream_timeout_shift_lrulist(struct streamindex *pindex, unsigned short new_timeout)
{
	unsigned short global_default_timeout;
	struct stream_list *lru_list_root;
	const struct streaminfo *pstream = &pindex->stream.stream_public;
	
	if(STREAM_TYPE_TCP == pindex->stream.stream_public.type){
		global_default_timeout = link_default_nopkt_time;
		lru_list_root=&(G_MESA_GLOBAL_STREAM[pstream->threadnum]->tcpList[pstream->stream_state]);
	}else{
		global_default_timeout = udp_reset_time;
		lru_list_root=&(G_MESA_GLOBAL_STREAM[pstream->threadnum]->udpList[pstream->stream_state]);
	}

	if(lru_list_root->cnt == 1){ /* 当前仅剩最后一个流, 无需移动 */
		return;
	}

	timeouts_add(lru_list_root->streamindex_timer, &pindex->timeout, new_timeout+g_CurrentTime);

	return;
}

/*
	NOTE: 
	    新设置的超时时间必须比全局标准timeout值大!!
	    因为全局所有流表只有一个LRU_time链表,
         设置新值很大, 可以将当前流从LRU末尾查找适当位置,
         但如果当前值比全局标准小, 可能需要从LRU链表的tail处查询很多个流才能找到适当位置,
         导致单包延时太长.
*/
int stream_set_single_stream_timeout(const struct streaminfo *pstream,unsigned short timeout)
{
	int ret=0;
	struct streaminfo_private *pstream_pr=(struct streaminfo_private *)pstream;
	struct streamindex *pindex;

	if(OP_STATE_CLOSE == pstream->opstate){/* 当前流已结束, 再设超时也没有意义了 */
		return -1;
	}
	
	if((0 == pstream_pr->timeout)  /* 0为从未设置过 */
	 || (timeout >= pstream_pr->timeout))  /* 新设置的超时值必须大于等于当前值 */
	{
	  /* TODO 1, 将此流移动到LRU超时链表适当的位置, 从head开始按剩余的超时时间排序。
	    NOTE:
	    因为可能全局都没开启超时, 但针对单个流设置了超时, 那么此流应该移动到LRU末尾,
		否则del_stream_by_time()函数只会判断最末尾的流是否超时, 不会判断其他的流.

		风险: 这类流为了保护包数少、持续时间长的流, 增加限制条件, 不能超过总流数的%p; 
	  */
		pindex = sapp_get_struct_header(pstream_pr, struct streamindex, stream); 

		if(STREAM_TYPE_UDP==pstream->type)
		{
			if(timeout < udp_reset_time){ /* 必须比全局默认值大, 且不能比之前设置的小 */
				return -1;
			}
			if(pstream_pr->timeout == udp_reset_time){ 
				/* 允许插件多次设置超时时间, 当前流第一次设置超时时间记录计数 */
				sapp_global_mthread[pstream->threadnum].udp_stream_special_timeout_num++;
			}
		}
		else if (STREAM_TYPE_TCP==pstream->type)
		{
			if(timeout < link_default_nopkt_time){ /* 必须比全局默认值大, 且不能比之前设置的小 */
				return -1;
			}		
			if(pstream_pr->timeout == link_default_nopkt_time){ 
				/* 允许插件多次设置超时时间, 当前流第一次设置超时时间记录计数 */
				sapp_global_mthread[pstream->threadnum].tcp_stream_special_timeout_num++;
			}
		}else{
			goto err; /* 仅支持TCP和UDP流 */
		}
	
	}
	else
	{
		goto err;
	}

	stream_timeout_shift_lrulist(pindex, timeout);
	
	pstream_pr->timeout=timeout;
	return ret;

err:
	return -1;
}

int udp_set_stream_num(int udp1,int udp2,int udp3)
{
	udpstate_num[UDP_ONE_STATE]=udp1;
	udpstate_num[UDP_TWO_STATE]=udp2;
	udpstate_num[UDP_MORE_STATE]=udp3;
	
	return 0;	
}



static struct streaminfo *del_stream(struct streamindex *pindex, unsigned char close_cause)
{
	struct streaminfo_private *pstream_pr=&(pindex->stream);
	struct streaminfo *pstream=&(pstream_pr->stream_public);

	pstream_pr->stream_close_reason = close_cause;
	
	if(STREAM_TYPE_UDP==pstream->type)
	{
		udp_free_stream(pindex);
	}
	else if (STREAM_TYPE_TCP==pstream->type)
	{
		if(STREAM_CLOSE_REASON_DUMPFILE == close_cause){
			((struct tcpdetail_private*)(pstream->pdetail))->link_state=STREAM_CLOSE_BY_DUMPFILE_END;
		}else{
			((struct tcpdetail_private*)(pstream->pdetail))->link_state=STREAM_LINK_LRU_OUT;
		}
		tcp_free_stream(pindex, NULL,NULL,NULL);
	}

	return NULL;
}

static inline void __do_streamleavlist(struct streamindex *pindex,struct stream_list *plist)
{

	//if (timeout_pending(&(pindex->timeout)))
	//{
		timeouts_del(plist->streamindex_timer, &pindex->timeout);
	//}
	plist->cnt -= 1;

	return;
}

void streamleavlist(struct streamindex *pindex,struct stream_list *plist)
{
	struct streaminfo *pstream=(struct streaminfo *)(&(pindex->stream));

	__do_streamleavlist(pindex, plist);

	update_stream_status(pstream->threadnum, pstream->type, pstream->stream_state, -1);
}


void streamaddlist(struct streamindex *pindex,struct stream_list *plist)
{
	int timeout_reason = STREAM_CLOSE_REASON_TIMEOUT;
	if(plist->cnt >= plist->max_cnt -1 && plist->cnt > 0)
	{
		if(plist->last_update_timer_s < g_CurrentTime)
		{
			timeouts_update(plist->streamindex_timer, g_CurrentTime);
			plist->last_update_timer_s = g_CurrentTime;
		}
		struct timeout *t = timeouts_get(plist->streamindex_timer);
		if(t == NULL)
		{
			struct timeouts_it it_all;
			TIMEOUTS_IT_INIT(&it_all, TIMEOUTS_ALL);
			t = timeouts_next(plist->streamindex_timer, &it_all);
			timeout_reason = STREAM_CLOSE_REASON_LRUOUT;
			assert(t!=NULL);
		}
		struct streamindex *pindex_tmp = container_of(t, struct streamindex, timeout);
		sapp_runtime_log(RLOG_LV_DEBUG, "streamaddlist trggier timeout, reason:%d,  thread:%d, timer_count:%d, create_time:%ld, lastmtime:%ld!",
				 timeout_reason,
				 pindex->stream.stream_public.threadnum,
				 pindex_tmp->stream.stream_public.ptcpdetail->createtime,
				 pindex_tmp->stream.stream_public.ptcpdetail->lastmtime);
		del_stream(pindex_tmp, timeout_reason);
	}
	
	struct streaminfo *pstream=(struct streaminfo *)(&(pindex->stream));
	long set_timeout = pindex->stream.timeout;
	if(set_timeout == 0)set_timeout = MAX_DEFALUT_TIMEOUT_S;
	timeout_init(&pindex->timeout, TIMEOUT_ABS);
	timeouts_add(plist->streamindex_timer, &pindex->timeout, set_timeout+g_CurrentTime);
	plist->cnt++;

	update_stream_status(pstream->threadnum, pstream->type, pstream->stream_state, 1);
}



struct streamindex *malloc_and_copy_streamindex(int threadnum, struct streamindex *pindex_stack)
{
	struct streamindex *pindex=NULL;
	struct global_stream *g_stream=G_MESA_GLOBAL_STREAM[threadnum];

	struct stream_index_list_item *list_item = STAILQ_FIRST(&g_stream->freeList);
	pindex = &list_item->index;
	UINT32 index = pindex->stream.stream_public.stream_index;
	STAILQ_REMOVE_HEAD(&g_stream->freeList, entries);
	g_stream->freeList_cnt--;
		
	memcpy(pindex,pindex_stack,sizeof(struct streamindex));

	pindex->stream.stream_public.stream_index=index;

	pindex->stream.stream_killed_flag = 0;
	pindex->stream.hash_not_head_times = 0;
	pindex->stream.stream_carry_up_layer_tunnel_type = 0;
	pindex->stream.stream_low_layer_tunnel_type = 0;

	//pindex->stream.global_stream_id = get_global_stream_id(threadnum);//移动到streamaddlist,四元组重用时不会被调用.
	
	return pindex;
	
}
void free_streamindex(int threadnum,struct streamindex *pindex)
{
	struct global_stream *g_stream=G_MESA_GLOBAL_STREAM[threadnum];
	if(STAILQ_EMPTY(&g_stream->freeList))
	{
		assert(0);
		STAILQ_INSERT_TAIL(&g_stream->freeList, (struct stream_index_list_item *)pindex, entries);
	}
	else
	{
		STAILQ_INSERT_TAIL(&g_stream->freeList, (struct stream_index_list_item *)pindex, entries);
		
	}
	g_stream->freeList_cnt++;
	
}

extern int call_streamentry(struct streaminfo *a_stream, const void *this_iphdr, const void *transport_hdr, const void *raw_pkt, StreamFunInfo *pFunInfo);
//add by lqy 20141203
//检测链表尾部的最后一个链接是否超时，如果超时则淘汰之

/* 2015-06-10 lijia add arg "current_drive_index", 表示当前流结构指针 
	return value:
		0: normal;
		1: del self by time.

	modify by lqy 20150612
	超时删除从链表头部开始，一次删除		
*/
int del_stream_by_time(struct stream_list *plist, const struct streamindex *current_drive_index, int thread_id)
{
	int ret = 0;
	struct global_stream *g_stream = G_MESA_GLOBAL_STREAM[thread_id];
	if(plist->last_update_timer_s < g_CurrentTime)
	{
		timeouts_update(plist->streamindex_timer, g_CurrentTime);
		if(g_stream->user_define_timer_cnt > 0)
		{
			timeouts_update(g_stream->user_define_timer, g_CurrentTime);
		}
		plist->last_update_timer_s = g_CurrentTime;
	}
	struct timeout *t = timeouts_get(plist->streamindex_timer);
	if (t != NULL)
	{
		struct streamindex *pindex = (struct streamindex *)sapp_get_struct_header(t, struct streamindex, timeout);
		struct streaminfo_private *pstream_pr = &(pindex->stream);
		struct streaminfo *pstream = &(pstream_pr->stream_public);

        if (pindex == current_drive_index)
        { /* 当前包所在的流超时, 说明之前很长时间没有包到来, 此时不用free, 而是返回1, 再调用reset */
            if (STREAM_TYPE_TCP == pstream->type)
            {
                /* 2016-12-15 lijia add, 超时reset之前, 先要设置link_state */
                ((struct tcpdetail_private *)(pstream->pdetail))->link_state = STREAM_LINK_TIMEOUT;
            }
            ret = 1;
        }
        else
        {
            if (STREAM_TYPE_TCP == pstream->type)
            {
                ((struct tcpdetail_private *)(pstream->pdetail))->link_state = STREAM_LINK_TIMEOUT;
                tcp_free_stream(pindex, NULL, NULL, NULL);
                ret = 2;
            }
            else
            {
                pstream_pr->stream_close_reason = STREAM_CLOSE_REASON_TIMEOUT;
                udp_free_stream(pindex);
                ret = 2;
            }
        }
    }
	if(g_stream->user_define_timer_cnt > 0)
	{
		t = timeouts_get(g_stream->user_define_timer);
		if (t != NULL)
		{
			StreamFunInfo *funinfo = (StreamFunInfo *)sapp_get_struct_header(t, StreamFunInfo, timeout);
			struct streaminfo *tstream = (struct streaminfo *)funinfo->pstream;
			unsigned char saved_op_state = tstream->opstate;
			unsigned char saved_pkt_state = tstream->pktstate;
			tstream->opstate = OP_STATE_TIMED;
			tstream->pktstate = OP_STATE_TIMED;
			int app_ret = call_streamentry((struct streaminfo *)funinfo->pstream, NULL, NULL, NULL, funinfo);
			tstream->opstate = saved_op_state;
			tstream->pktstate = saved_pkt_state;

			if(app_ret == APP_STATE_GIVEME)
			{
				timeouts_add(g_stream->user_define_timer, t, funinfo->set_timer_s+g_CurrentTime);
			}
			else
			{
				g_stream->user_define_timer_cnt -= 1;
			}
		}
	}
	return ret;
}

/*
	return value:
		0: normal;
		1: del self by timeout, need reset.
*/
int lrustream(struct streamindex *pindex)
{
	struct stream_list *plist=NULL;
	struct streaminfo_private *pstream_pr=&(pindex->stream);
	struct streaminfo *pstream = &pstream_pr->stream_public;
	
	if(STREAM_TYPE_UDP==pstream->type)
	{
		plist=&(G_MESA_GLOBAL_STREAM[pstream->threadnum]->udpList[pstream->stream_state]);

	}
	else if (STREAM_TYPE_TCP==pstream->type)
	{
		plist=&(G_MESA_GLOBAL_STREAM[pstream->threadnum]->tcpList[pstream->stream_state]);

	}
	//if(g_CurrentTime > plist->last_check_timer_s)
	{
		int ret  = del_stream_by_time(plist, pindex, pstream->threadnum);
		if (1 == ret)
		{
			return 1;
		}
	}
	long set_timeout = pindex->stream.timeout;
	if(set_timeout == 0)set_timeout = MAX_DEFALUT_TIMEOUT_S;
	timeouts_add(plist->streamindex_timer, &pindex->timeout, g_CurrentTime+set_timeout);
	
	return 0;
}

/*
	MPLS层地址不像ipv4,ipv6,tcp,udp那样, 收到任意一个包可以推断另一侧的地址,
	MPLS地址是单向的, 甚至还有可能是不对称存在的, 即一侧有而另一侧没有.
	所以, 比较地址不分方向.
*/
static int cmpaddr_mpls(const struct layer_addr_mpls *addr_heap, const struct layer_addr_mpls  *addr_stack)
{
	int i, ret = 0;
	int same_dir_diff = 0, reverse_dir_diff = 0;
	
	if(0 == addr_stack->c2s_layer_num){
		return 0; /* 新来的包mpls是空层, 不用比较 */
	}

	if((addr_heap->c2s_layer_num == 0) || (addr_heap->s2c_layer_num == 0)){
		/* 如果堆里的地址某一侧是0, 也许是单向流, 即还没收到过对侧流量;
		   也许是某一侧是空层, 根本就没有mpls, 
		   此时没法判断是一个流对侧数据包首次到达, 还是根本不是一个隧道的另一个新流首次到达,
		   先不比较地址了. 
		*/
		return 0;
	}

	/* 正向比较地址 */
	if(addr_heap->c2s_layer_num != addr_stack->c2s_layer_num){
		same_dir_diff = 1;
	}else{
		for(i = 0; i < addr_heap->c2s_layer_num; i++){
			if(addr_heap->c2s_addr_array[i].label != addr_stack->c2s_addr_array[i].label){
				same_dir_diff = 1;
				break;
			}
		}
	}

	/* 反向比较地址 */
	if(addr_heap->s2c_layer_num != addr_stack->c2s_layer_num){
		reverse_dir_diff = 1;
	}else{
		for(i = 0; i < addr_heap->s2c_layer_num; i++){
			if(addr_heap->s2c_addr_array[i].label != addr_stack->s2c_addr_array[i].label){
				reverse_dir_diff = 1;
				break;
			}
		}
	}

	if(same_dir_diff && reverse_dir_diff){ /* 两个方向地址都不一样 */
		return -1;
	}

	return ret;
}

static int cmpaddr_gtp(const struct layer_addr_gtp *addr_heap, const struct layer_addr_gtp  *addr_stack)
{
	/* stack 的地址固定存储于c2s方向
		gtp地址比较时, 不分方向, 有任意方向的teid能相同, 就认为是一个隧道，
		之前的pcap包有发现外层地址和某一侧的teid都变化的情况.
	*/
	if(0 != addr_heap->teid_c2s){
		if(addr_heap->teid_c2s == addr_stack->teid_c2s){
			return 0 ;
		}
	}

	if(addr_heap->teid_s2c != 0){
		if(addr_heap->teid_s2c == addr_stack->teid_c2s){
			return 0 ;
		}
	}

	return -1;
}

static int  cmpaddr_positive(void *addr_heap, void *addr_stack, UCHAR addrtype, UCHAR addrlen)
{
	int ret;
	
	switch(addrtype){
		case ADDR_TYPE_IPV4:
		{
			/* 2015-07-14 lijia modify, 需要比较端口 */
			struct stream_tuple4_v4 *ip4_addr_heap = (struct stream_tuple4_v4 *)addr_heap;
			struct stream_tuple4_v4 *ip4_addr_stack = (struct stream_tuple4_v4 *)addr_stack;

			/* 2015-07-15 lijia modify, 最可能不一样的变量放在最前面比较 */
			ret = (int)ip4_addr_heap->source - (int)ip4_addr_stack->source;
			if(ret != 0){
				return ret;
			}
			ret = (int)ip4_addr_heap->saddr - (int)ip4_addr_stack->saddr;
			if(ret != 0){
				return ret;
			}
			ret = (int)ip4_addr_heap->daddr - (int)ip4_addr_stack->daddr;
			if(ret != 0){
				return ret;
			}
			ret = (int)ip4_addr_heap->dest - (int)ip4_addr_stack->dest;
			if(ret != 0){
				return ret;
			}			
		}
		break;

		case ADDR_TYPE_IPV6:
		{
			struct stream_tuple4_v6 *ip6_addr_heap = (struct stream_tuple4_v6 *)addr_heap;
			struct stream_tuple4_v6 *ip6_addr_stack = (struct stream_tuple4_v6 *)addr_stack;
			/* 2015-07-15 lijia modify, 最可能不一样的变量放在最前面比较 */
			ret = (int)ip6_addr_heap->source - (int)ip6_addr_stack->source;
			if(ret != 0){
				return ret;
			}		
			ret = memcmp(ip6_addr_heap->saddr, ip6_addr_stack->saddr, IPV6_ADDR_LEN);
			if(ret != 0){
				return ret;
			}
			ret = memcmp(ip6_addr_heap->daddr, ip6_addr_stack->daddr, IPV6_ADDR_LEN);
			if(ret != 0){
				return ret;
			}
			ret = (int)ip6_addr_heap->dest - (int)ip6_addr_stack->dest;	
			if(ret != 0){
				return ret;
			}			
		}
		break;

		case __ADDR_TYPE_IP_PAIR_V4:	
		{
			struct stream_tuple4_v4 *pure_ip4_addr_heap = (struct stream_tuple4_v4 *)addr_heap;
			struct stream_tuple4_v4 *pure_ip4_addr_stack = (struct stream_tuple4_v4 *)addr_stack;

			ret = (int)pure_ip4_addr_heap->saddr - (int)pure_ip4_addr_stack->saddr;
			if(ret != 0){
				return ret;
			}
			ret = (int)pure_ip4_addr_heap->daddr - (int)pure_ip4_addr_stack->daddr;
			if(ret != 0){
				return ret;
			}
		}
		break;
		
		case __ADDR_TYPE_IP_PAIR_V6:
		{
			struct stream_tuple4_v6 *pure_ip6_addr_heap = (struct stream_tuple4_v6 *)addr_heap;
			struct stream_tuple4_v6 *pure_ip6_addr_stack = (struct stream_tuple4_v6 *)addr_stack;
	
			ret = memcmp(pure_ip6_addr_heap->saddr, pure_ip6_addr_stack->saddr, IPV6_ADDR_LEN);
			if(ret != 0){
				return ret;
			}
			ret = memcmp(pure_ip6_addr_heap->daddr, pure_ip6_addr_stack->daddr, IPV6_ADDR_LEN);
			if(ret != 0){
				return ret;
			}		
		}
		break;

		case ADDR_TYPE_MPLS:
			ret = cmpaddr_mpls((struct layer_addr_mpls *)addr_heap, (struct layer_addr_mpls *)addr_stack);
		break;

		case ADDR_TYPE_GPRS_TUNNEL:
			ret = cmpaddr_gtp((struct layer_addr_gtp *)addr_heap, (struct layer_addr_gtp *)addr_stack);
		break;
		
		default:
			/* 其他地址类型, 如VLAN, L2TP等, 无方向性特征, 无需转换, 直接比较即可 */
			ret = memcmp(addr_heap, addr_stack, addrlen);
	}

	return ret;
}
static int  cmpaddr_reverse(void *addr_heap, void *addr_stack, UCHAR addrtype, UCHAR addrlen)
{
	int ret;
	
	switch(addrtype){
		case ADDR_TYPE_IPV4:
		{
			/* 2015-07-14 lijia modify, 需要比较端口 */
			struct stream_tuple4_v4 *ip4_addr_heap = (struct stream_tuple4_v4 *)addr_heap;
			struct stream_tuple4_v4 *ip4_addr_stack = (struct stream_tuple4_v4 *)addr_stack;

			/* 2015-07-15 lijia modify, 最可能不一样的变量放在最前面比较 */
			ret = (int)ip4_addr_heap->source - (int)ip4_addr_stack->dest;
			if(ret != 0){
				return ret;
			}
			ret = (int)ip4_addr_heap->saddr - (int)ip4_addr_stack->daddr;
			if(ret != 0){
				return ret;
			}
			ret = (int)ip4_addr_heap->daddr - (int)ip4_addr_stack->saddr;
			if(ret != 0){
				return ret;
			}
			ret = (int)ip4_addr_heap->dest - (int)ip4_addr_stack->source;
			if(ret != 0){
				return ret;
			}			
		}
		break;

		case ADDR_TYPE_IPV6:
		{
			struct stream_tuple4_v6 *ip6_addr_heap = (struct stream_tuple4_v6 *)addr_heap;
			struct stream_tuple4_v6 *ip6_addr_stack = (struct stream_tuple4_v6 *)addr_stack;
			/* 2015-07-15 lijia modify, 最可能不一样的变量放在最前面比较 */
			ret = (int)ip6_addr_heap->source - (int)ip6_addr_stack->dest;
			if(ret != 0){
				return ret;
			}		
			ret = memcmp(ip6_addr_heap->saddr, ip6_addr_stack->daddr, IPV6_ADDR_LEN);
			if(ret != 0){
				return ret;
			}
			ret = memcmp(ip6_addr_heap->daddr, ip6_addr_stack->saddr, IPV6_ADDR_LEN);
			if(ret != 0){
				return ret;
			}
			ret = (int)ip6_addr_heap->dest - (int)ip6_addr_stack->source;	
			if(ret != 0){
				return ret;
			}				
		}
		break;

		case __ADDR_TYPE_IP_PAIR_V4:	
		{
			struct stream_tuple4_v4 *pure_ip4_addr_heap = (struct stream_tuple4_v4 *)addr_heap;
			struct stream_tuple4_v4 *pure_ip4_addr_stack = (struct stream_tuple4_v4 *)addr_stack;

			ret = (int)pure_ip4_addr_heap->saddr - (int)pure_ip4_addr_stack->daddr;
			if(ret != 0){
				return ret;
			}
			ret = (int)pure_ip4_addr_heap->daddr - (int)pure_ip4_addr_stack->saddr;
			if(ret != 0){
				return ret;
			}
		}
		break;

		case __ADDR_TYPE_IP_PAIR_V6:
		{
			struct stream_tuple4_v6 *pure_ip6_addr_heap = (struct stream_tuple4_v6 *)addr_heap;
			struct stream_tuple4_v6 *pure_ip6_addr_stack = (struct stream_tuple4_v6 *)addr_stack;
	
			ret = memcmp(pure_ip6_addr_heap->saddr, pure_ip6_addr_stack->daddr, IPV6_ADDR_LEN);
			if(ret != 0){
				return ret;
			}
			ret = memcmp(pure_ip6_addr_heap->daddr, pure_ip6_addr_stack->saddr, IPV6_ADDR_LEN);
			if(ret != 0){
				return ret;
			}		
		}
		break;

		case ADDR_TYPE_MPLS:
			ret = cmpaddr_mpls((struct layer_addr_mpls *)addr_heap, (struct layer_addr_mpls *)addr_stack);
		break;		

		case ADDR_TYPE_GPRS_TUNNEL:
			ret = cmpaddr_gtp((struct layer_addr_gtp *)addr_heap, (struct layer_addr_gtp *)addr_stack);
		break;		
		
		default:
			/* 其他地址类型, 如VLAN, L2TP等, 无方向性特征, 无需转换 */
			ret = memcmp(addr_heap, addr_stack, addrlen);
	}

	return ret;
}

/*
	pheap_stream_pr : already in stream htable.
	pstack_stream_pr: new element recv from network;
*/
static int cmpaddr_new(struct streaminfo_private *pheap_stream_pr, 
					struct streaminfo_private *pstack_stream_pr)
{
	int ret;
	struct layer_addr *heap_addr, *stack_addr;

	heap_addr = &pheap_stream_pr->stream_public.addr;
	stack_addr = &pstack_stream_pr->stream_public.addr;

	if(pheap_stream_pr->stream_dir == pstack_stream_pr->layer_dir){
		ret = cmpaddr_positive(heap_addr->paddr,  stack_addr->paddr,
							heap_addr->addrtype, heap_addr->addrlen);
	}else{
		/* 2015-03-04 lijia add, 反向地址比较, 无需先COPY.*/	
		ret = cmpaddr_reverse(heap_addr->paddr,  stack_addr->paddr,
							heap_addr->addrtype, heap_addr->addrlen);
	}
	
	if(0 == ret){
		//pst1->p_layer_header = pst2->p_layer_header;
		pheap_stream_pr->offset_to_raw_pkt_hdr = pstack_stream_pr->offset_to_raw_pkt_hdr;
	}

	return ret;
}


/*
	GTP的端口可能两侧都不一样, 即asymmetric addr,
	此处更新端口以最后一次ip或teid改变的包为准.
*/
static void update_outer_ipv4addr_for_gtp_tunnel(const struct streaminfo_private *top_stream_pr, 
	struct streaminfo_private *pheap_gtp_stream_pr, struct streaminfo_private *pstack_gtp_stream_pr,
	struct streaminfo_private *pheap_ip_stream_pr, struct streaminfo_private *pstack_ip_stream_pr, unsigned char cur_pkt_dir)
{
	int addr_has_changed = 0;
	const struct stream_tuple4_v4 *stack_tuple4addr = pstack_ip_stream_pr->stream_public.addr.tuple4_v4;
	struct stream_tuple4_v4 *heap_tuple4addr = pheap_ip_stream_pr->stream_public.addr.tuple4_v4;
	
	if(DIR_C2S == cur_pkt_dir){
		if(heap_tuple4addr->saddr != stack_tuple4addr->saddr){
			addr_has_changed = 1;
		}
		if(heap_tuple4addr->daddr != stack_tuple4addr->daddr){
			addr_has_changed = 1;
		}
		if(pheap_gtp_stream_pr->stream_public.addr.gtp->teid_c2s != pstack_gtp_stream_pr->stream_public.addr.gtp->teid_c2s){
			addr_has_changed = 1;
		}
	}else{
		if(heap_tuple4addr->saddr != stack_tuple4addr->daddr){
			addr_has_changed = 1;
		}
		if(heap_tuple4addr->daddr != stack_tuple4addr->saddr){
			addr_has_changed = 1;
		}		
		if(pheap_gtp_stream_pr->stream_public.addr.gtp->teid_s2c != pstack_gtp_stream_pr->stream_public.addr.gtp->teid_c2s){
			addr_has_changed = 1;
		}		
	}	

	if(likely(0 == addr_has_changed)){
		return;
	}

	/******** for debug log, 要放在地址更新的前面, 否则原始信息就被覆盖了 ********/
	if(ABBR_SAPP_LOG_LEVEL <= RLOG_LV_DEBUG){
		char ip_before_src_str[INET_ADDRSTRLEN], ip_before_dst_str[INET_ADDRSTRLEN];
		char ip_after_src_str[INET_ADDRSTRLEN], ip_after_dst_str[INET_ADDRSTRLEN];
		unsigned int before_teid_c2s, before_teid_s2c, after_teid_c2s, after_teid_s2c;
		
		//if(addr_has_changed)
		{
			before_teid_c2s = ntohl(pheap_gtp_stream_pr->stream_public.addr.gtp->teid_c2s);
			before_teid_s2c = ntohl(pheap_gtp_stream_pr->stream_public.addr.gtp->teid_s2c);
		
			if(DIR_C2S == cur_pkt_dir){
				after_teid_c2s = ntohl(pstack_gtp_stream_pr->stream_public.addr.gtp->teid_c2s);
				after_teid_s2c = before_teid_s2c;
			}else{
				after_teid_s2c = ntohl(pstack_gtp_stream_pr->stream_public.addr.gtp->teid_c2s); /* 此处不是笔误!! stack是临时栈空间, teid固定放在c2s变量中 */
				after_teid_c2s = before_teid_c2s;	
			}
		
			inet_ntop(AF_INET, &heap_tuple4addr->saddr, ip_before_src_str, sizeof(ip_before_src_str));
			inet_ntop(AF_INET, &heap_tuple4addr->daddr, ip_before_dst_str, sizeof(ip_before_dst_str));
			inet_ntop(AF_INET, &stack_tuple4addr->saddr, ip_after_src_str, sizeof(ip_after_src_str));
			inet_ntop(AF_INET, &stack_tuple4addr->daddr, ip_after_dst_str, sizeof(ip_after_dst_str));			
			sapp_runtime_log(RLOG_LV_DEBUG, "stream:%s, curdir:%d, for GTP tunnel, outer tuple4 addr has changed, before IP:%s->%s, after IP:%s->%s, before TEID:%u->%u, after TEID:%u->%u,",
							printaddr(&top_stream_pr->stream_public.addr, top_stream_pr->stream_public.threadnum), cur_pkt_dir,
							ip_before_src_str, ip_before_dst_str, ip_after_src_str, ip_after_dst_str,
							before_teid_c2s, before_teid_s2c, after_teid_c2s, after_teid_s2c);
		}
	}

	if(DIR_C2S == cur_pkt_dir){
		heap_tuple4addr->saddr = stack_tuple4addr->saddr;
		heap_tuple4addr->daddr = stack_tuple4addr->daddr;
		heap_tuple4addr->source = stack_tuple4addr->source;
		heap_tuple4addr->dest = stack_tuple4addr->dest;		
		pheap_gtp_stream_pr->stream_public.addr.gtp->teid_c2s = pstack_gtp_stream_pr->stream_public.addr.gtp->teid_c2s;

	}else{
		heap_tuple4addr->saddr = stack_tuple4addr->daddr;
		heap_tuple4addr->daddr = stack_tuple4addr->saddr;
		heap_tuple4addr->source = stack_tuple4addr->dest;
		heap_tuple4addr->dest = stack_tuple4addr->source;	
		pheap_gtp_stream_pr->stream_public.addr.gtp->teid_s2c = pstack_gtp_stream_pr->stream_public.addr.gtp->teid_c2s; /* 此处不是笔误!! stack是临时栈空间, teid固定放在c2s变量中 */
	}	

	return;
}

static void update_outer_ipv6addr_for_gtp_tunnel(const struct streaminfo_private *top_stream_pr, 
	struct streaminfo_private *pheap_gtp_stream_pr, struct streaminfo_private *pstack_gtp_stream_pr,
	struct streaminfo_private *pheap_ip_stream_pr, struct streaminfo_private *pstack_ip_stream_pr, unsigned char cur_pkt_dir)
{
	int addr_has_changed = 0;
	const struct stream_tuple4_v6 *stack_tuple6addr = pstack_ip_stream_pr->stream_public.addr.tuple4_v6;
	struct stream_tuple4_v6 *heap_tuple6addr = pheap_ip_stream_pr->stream_public.addr.tuple4_v6;
	
	if(DIR_C2S == cur_pkt_dir){
		if(memcmp(heap_tuple6addr->saddr, stack_tuple6addr->saddr, IPV6_ADDR_LEN)){
			addr_has_changed = 1;
		}
		if(memcmp(heap_tuple6addr->daddr, stack_tuple6addr->daddr, IPV6_ADDR_LEN)){
			addr_has_changed = 1;
		}
		if(pheap_gtp_stream_pr->stream_public.addr.gtp->teid_c2s != pstack_gtp_stream_pr->stream_public.addr.gtp->teid_c2s){
			addr_has_changed = 1;
		}
	}else{
		if(memcmp(heap_tuple6addr->saddr, stack_tuple6addr->daddr, IPV6_ADDR_LEN)){
			addr_has_changed = 1;
		}
		if(memcmp(heap_tuple6addr->daddr, stack_tuple6addr->saddr, IPV6_ADDR_LEN)){
			addr_has_changed = 1;
		}		
		if(pheap_gtp_stream_pr->stream_public.addr.gtp->teid_s2c != pstack_gtp_stream_pr->stream_public.addr.gtp->teid_c2s){
			addr_has_changed = 1;
		}		
	}	

	if(likely(0 == addr_has_changed)){
		return;
	}

	/******** for debug log, 要放在地址更新的前面, 否则原始信息就被覆盖了 ********/
	if(ABBR_SAPP_LOG_LEVEL <= RLOG_LV_DEBUG){
		char ip_before_src_str[INET_ADDRSTRLEN], ip_before_dst_str[INET_ADDRSTRLEN];
		char ip_after_src_str[INET_ADDRSTRLEN], ip_after_dst_str[INET_ADDRSTRLEN];
		unsigned int before_teid_c2s, before_teid_s2c, after_teid_c2s, after_teid_s2c;
		
		//if(addr_has_changed)
		{
			before_teid_c2s = ntohl(pheap_gtp_stream_pr->stream_public.addr.gtp->teid_c2s);
			before_teid_s2c = ntohl(pheap_gtp_stream_pr->stream_public.addr.gtp->teid_s2c);
		
			if(DIR_C2S == cur_pkt_dir){
				after_teid_c2s = ntohl(pstack_gtp_stream_pr->stream_public.addr.gtp->teid_c2s);
				after_teid_s2c = before_teid_s2c;
			}else{
				after_teid_s2c = ntohl(pstack_gtp_stream_pr->stream_public.addr.gtp->teid_c2s); /* 此处不是笔误!! stack是临时栈空间, teid固定放在c2s变量中 */
				after_teid_c2s = before_teid_c2s;	
			}
		
			inet_ntop(AF_INET, &heap_tuple6addr->saddr, ip_before_src_str, sizeof(ip_before_src_str));
			inet_ntop(AF_INET, &heap_tuple6addr->daddr, ip_before_dst_str, sizeof(ip_before_dst_str));
			inet_ntop(AF_INET, &stack_tuple6addr->saddr, ip_after_src_str, sizeof(ip_after_src_str));
			inet_ntop(AF_INET, &stack_tuple6addr->daddr, ip_after_dst_str, sizeof(ip_after_dst_str));			
			sapp_runtime_log(RLOG_LV_DEBUG, "stream:%s, curdir:%d, for GTP tunnel, outer tuple4 addr has changed, before IP:%s->%s, after IP:%s->%s, before TEID:%u->%u, after TEID:%u->%u,",
							printaddr(&top_stream_pr->stream_public.addr, top_stream_pr->stream_public.threadnum), cur_pkt_dir,
							ip_before_src_str, ip_before_dst_str, ip_after_src_str, ip_after_dst_str,
							before_teid_c2s, before_teid_s2c, after_teid_c2s, after_teid_s2c);
		}
	}

	if(DIR_C2S == cur_pkt_dir){

		//heap_tuple6addr->saddr = stack_tuple6addr->saddr;
		memcpy(heap_tuple6addr->saddr, stack_tuple6addr->saddr, IPV6_ADDR_LEN);		
		//heap_tuple6addr->daddr = stack_tuple6addr->daddr;
		memcpy(heap_tuple6addr->daddr, stack_tuple6addr->daddr, IPV6_ADDR_LEN);
		heap_tuple6addr->source = stack_tuple6addr->source;
		heap_tuple6addr->dest = stack_tuple6addr->dest;		
		pheap_gtp_stream_pr->stream_public.addr.gtp->teid_c2s = pstack_gtp_stream_pr->stream_public.addr.gtp->teid_c2s;

	}else{
		//heap_tuple6addr->saddr = stack_tuple6addr->daddr;		
		memcpy(heap_tuple6addr->saddr, stack_tuple6addr->daddr, IPV6_ADDR_LEN);		
		//heap_tuple6addr->daddr = stack_tuple6addr->saddr;		
		memcpy(heap_tuple6addr->daddr, stack_tuple6addr->saddr, IPV6_ADDR_LEN);		
		heap_tuple6addr->source = stack_tuple6addr->dest;
		heap_tuple6addr->dest = stack_tuple6addr->source;	
		pheap_gtp_stream_pr->stream_public.addr.gtp->teid_s2c = pstack_gtp_stream_pr->stream_public.addr.gtp->teid_c2s; /* 此处不是笔误!! stack是临时栈空间, teid固定放在c2s变量中 */
	}	

	return;
}

/*
	GTP隧道的外层IP四元组, 因基站的迁移, 外层IP可能变化.

	pheap_stream_pr, pstack_stream_pr指向GTP下一层的ip/udp层.
*/
static int checkstreamorder_for_gtp_tunnel(const struct streaminfo_private *top_stream_pr, 
	struct streaminfo_private *pheap_gtp_stream_pr, struct streaminfo_private *pstack_gtp_stream_pr,
	struct streaminfo_private *pheap_ip_stream_pr, struct streaminfo_private *pstack_ip_stream_pr, 
	int *heap_streaminfo_skip_layer_num, int *stack_streaminfo_skip_layer_num)
{
	int ret;
	const struct streaminfo * pheap_stream = &pheap_ip_stream_pr->stream_public;
	const struct streaminfo * pstack_stream = &pstack_ip_stream_pr->stream_public;
	int this_layer_is_same = 0;
	unsigned char cur_pkt_dir;
	
	if(pheap_ip_stream_pr==NULL){
		if(unlikely(pstack_ip_stream_pr!=NULL)){		
			return -1;
		}else{	
			return 0;
		}
	}else{
		if(unlikely(pstack_ip_stream_pr==NULL)){			
			return 1;
		}	
	}	
	
	/* 外层ip地址会变化, 但四个ip不可能都不一样, 有任意方向地址相同, 即可认为是来自同一个GTP隧道
		TODO, 此处需要同GTP-C联动 ??
	*/
	if (pheap_stream->addr.addrtype == ADDR_TYPE_IPV4)
	{
		if (pheap_stream->addr.tuple4_v4->saddr == pstack_stream->addr.tuple4_v4->saddr)
		{
			this_layer_is_same = 1;
			cur_pkt_dir = DIR_C2S;
		}
		else if (pheap_stream->addr.tuple4_v4->daddr == pstack_stream->addr.tuple4_v4->daddr)
		{
			this_layer_is_same = 1;
			cur_pkt_dir = DIR_C2S;
		}
		else if (pheap_stream->addr.tuple4_v4->saddr == pstack_stream->addr.tuple4_v4->daddr)
		{
			this_layer_is_same = 1;
			cur_pkt_dir = DIR_S2C;
		}
		else if (pheap_stream->addr.tuple4_v4->daddr == pstack_stream->addr.tuple4_v4->saddr)
		{
			this_layer_is_same = 1;
			cur_pkt_dir = DIR_S2C;
		}
	}
	else if(pheap_stream->addr.addrtype == ADDR_TYPE_IPV6)
	{
		if (0 == memcmp(pheap_stream->addr.tuple4_v6->saddr,pstack_stream->addr.tuple4_v6->saddr, IPV6_ADDR_LEN))
		{
			this_layer_is_same = 1;
			cur_pkt_dir = DIR_C2S;
		}
		else if (0 == memcmp(pheap_stream->addr.tuple4_v6->daddr,pstack_stream->addr.tuple4_v6->daddr, IPV6_ADDR_LEN))
		{
			this_layer_is_same = 1;
			cur_pkt_dir = DIR_C2S;
		}
		else if (0 == memcmp(pheap_stream->addr.tuple4_v6->saddr,pstack_stream->addr.tuple4_v6->daddr, IPV6_ADDR_LEN))
		{
			this_layer_is_same = 1;
			cur_pkt_dir = DIR_S2C;
		}
		else if (0 == memcmp(pheap_stream->addr.tuple4_v6->daddr,pstack_stream->addr.tuple4_v6->saddr, IPV6_ADDR_LEN))
		{
			this_layer_is_same = 1;
			cur_pkt_dir = DIR_S2C;
		}
	}
	else
	{
		sapp_runtime_log(RLOG_LV_FATAL, "stream:%s, curdir:%d, addrtype:%d for GTP tunnel, heap stream tuple4 addr not IPv4 or IPv6",
				 printaddr(&top_stream_pr->stream_public.addr, top_stream_pr->stream_public.threadnum), cur_pkt_dir, pheap_stream->addr.addrtype);
	}

	if(0 == this_layer_is_same){ /* 本层地址全不一样, 认为不是来自一个隧道, 直接返回错误 */
		return -1;
	}

	/* 继续比较下一层地址 */
	ret=checkstreamorder(top_stream_pr, (struct streaminfo_private *)(pheap_ip_stream_pr->pfather_pr), 
						 (struct streaminfo_private *)(pstack_ip_stream_pr->pfather_pr),
						 heap_streaminfo_skip_layer_num, stack_streaminfo_skip_layer_num);

	if(0 == ret){
		/* 执行到此, 所有地址都相同, 或者是不用于地址比较, 说明当前流pheap_stream_pr,pstack_stream_pr是同属于一个上层TCP/UDP流,
			尝试更新外层的ipv4/udp流信息.
		*/

		if(pheap_stream->addr.addrtype == ADDR_TYPE_IPV4)
		{
			update_outer_ipv4addr_for_gtp_tunnel(top_stream_pr, pheap_gtp_stream_pr, pstack_gtp_stream_pr, pheap_ip_stream_pr, pstack_ip_stream_pr, cur_pkt_dir);
		}
		else if(pheap_stream->addr.addrtype == ADDR_TYPE_IPV6)
		{
			update_outer_ipv6addr_for_gtp_tunnel(top_stream_pr, pheap_gtp_stream_pr, pstack_gtp_stream_pr, pheap_ip_stream_pr, pstack_ip_stream_pr, cur_pkt_dir);
		}
	}

	return ret;

}

/*比较两个流结构体大小 */
//adjust 20140324 比较两个流结构是否相同，必须pfather 内的完全相同,
//递归比较两个流的父流的情况
/*
	return value:
		0 : found, success;
		1 : pst1 > pst2;
		-1: pst1 < pst2
*/
int checkstreamorder(const struct streaminfo_private *top_stream_pr, struct streaminfo_private *pheap_stream_pr,
		struct streaminfo_private *pstack_stream_pr, int *heap_streaminfo_skip_layer_num, int *stack_streaminfo_skip_layer_num)
{
	int ret;
	struct streaminfo *pheap_stream;
	struct streaminfo *pstack_stream;

	while((pheap_stream_pr != NULL) && (0 == pheap_stream_pr->addr_use_as_hash))
	{
		pheap_stream_pr = pheap_stream_pr->pfather_pr;
		*heap_streaminfo_skip_layer_num += 1;
	}	

	while((pstack_stream_pr != NULL) && (0 == pstack_stream_pr->addr_use_as_hash))
	{
		pstack_stream_pr = pstack_stream_pr->pfather_pr;
		*stack_streaminfo_skip_layer_num += 1;
	}		

	if(pheap_stream_pr==NULL)
	{
		if(unlikely(pstack_stream_pr!=NULL)){		
			return -1;
		}else{	
			return 0;
		}
	}
	else
	{
		if(unlikely(pstack_stream_pr==NULL)){			
			return 1;
		}	
	}	

	pheap_stream = &pheap_stream_pr->stream_public;
	pstack_stream = &pstack_stream_pr->stream_public;


	/*  GTP的TEID会变化, 不能简单的比较addr内容, 所以本层addr_use_as_hash=0,
	    所以会跳过gtp而比较下层的ip/udp, 但是外层的ip和端口可能会漂移, 也不能按常规方式比较ip和port,
		所以GTP加一个特殊处理.
	*/
	switch(pstack_stream->addr.addrtype){
		case ADDR_TYPE_GPRS_TUNNEL:
			return checkstreamorder_for_gtp_tunnel(top_stream_pr, pheap_stream_pr, pstack_stream_pr,
								(struct streaminfo_private *)(pheap_stream_pr->pfather_pr), 
								(struct streaminfo_private *)(pstack_stream_pr->pfather_pr),
								heap_streaminfo_skip_layer_num, stack_streaminfo_skip_layer_num);
		break;

		default:
		break;
	}

	
	ret = (int)(pheap_stream->type - pstack_stream->type);
	if(ret != 0)
	{
		return ret;
	}

	ret = (int)(pheap_stream->addr.addrtype - pstack_stream->addr.addrtype);
	if(ret != 0)
      {
	   return ret;
	}

	ret = cmpaddr_new(pheap_stream_pr, pstack_stream_pr);
	if(0 != ret){
		return ret;
	}else{
		/* 2015-03-11 lijia add, 需要将当前新IP层的包信息传递到流信息 */
		pheap_stream_pr->stream_public.addr.pktipfragtype = pstack_stream_pr->stream_public.addr.pktipfragtype;
	}
	
	ret=checkstreamorder(top_stream_pr, (struct streaminfo_private *)(pheap_stream_pr->pfather_pr), 
						 (struct streaminfo_private *)(pstack_stream_pr->pfather_pr),
						 heap_streaminfo_skip_layer_num, stack_streaminfo_skip_layer_num);
	if(ret != 0)
	{
	   return ret;
	}
	pheap_stream_pr->offset_to_raw_pkt_hdr = pstack_stream_pr->offset_to_raw_pkt_hdr;
	
	return ret;
}

/*
	用于非对称协议层数的对准.

	例如:
		heap stream : tuple4->eth,
		stack stream: tuple4->mpls->eth,
		这种情况下, 可以认为内层tcp是同属于一个流.

	对准之后:
	    heap stream : tuple4->mpls->eth
*/
static void streaminfo_layer_alignment(const struct streaminfo *top_stream, struct streaminfo_private *heap_stream_pr, struct streaminfo_private *stack_stream_pr)
{
	struct streaminfo_private *new_heap_tmp = NULL;
	int mem_used_type;
	
	if((NULL == heap_stream_pr) || (NULL == stack_stream_pr)){
		return;
	}

	if((NULL == heap_stream_pr->pfather_pr) || (NULL == stack_stream_pr->pfather_pr)){
		return;
	}

	if(heap_stream_pr->pfather_pr->stream_public.addr.addrtype != stack_stream_pr->pfather_pr->stream_public.addr.addrtype){
		/*
			new_heap_tmp此时执向mpls层
		*/
		if(STREAM_TYPE_TCP == top_stream->type){
			mem_used_type = SAPP_MEM_DYN_TCP_STREAM;
		}else{
			mem_used_type = SAPP_MEM_DYN_UDP_STREAM;
		}
		new_heap_tmp = copy_stream_info_to_heap_single_layer(mem_used_type, stack_stream_pr->pfather_pr, 1); /* 流对准时, 肯定是对侧来包, 反向copy, 因为同向就不存在层数不一致了, reverse固定为1 */

		new_heap_tmp->pfather_pr = heap_stream_pr->pfather_pr;
		new_heap_tmp->stream_public.pfather = &heap_stream_pr->pfather_pr->stream_public;
		heap_stream_pr->pfather_pr = new_heap_tmp;
		heap_stream_pr->stream_public.pfather = &new_heap_tmp->stream_public;

		sapp_runtime_log(RLOG_LV_DEBUG, "stream:%s, insert new asymmetric layer, addrtype:%d\n", 
						printaddr(&top_stream->addr, top_stream->threadnum), new_heap_tmp->stream_public.addr.addrtype);
	}

	streaminfo_layer_alignment(top_stream, heap_stream_pr->pfather_pr, stack_stream_pr->pfather_pr);
}

/*
	plinkhead: 已创建的流在htable中某个slot的第一个节点;
	pinsert  : 当前来包的临时栈空间流地址.
*/
static struct streamindex * findandsethashindex_lru(struct streamindex *plinkhead, struct streamindex *pinsert)
{
	struct streamindex *phead=plinkhead;
	struct streamindex  *res = NULL;
	struct streaminfo_private *pshead_pr=NULL;
	struct streaminfo_private *psinsert_pr=&(pinsert->stream);
	int result;
	unsigned long hash_list_num = 0;
	UCHAR threadnum = psinsert_pr->stream_public.threadnum;
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[threadnum]->sys_stat;
	int stack_streaminfo_skip_layer_num = 0, heap_streaminfo_skip_layer_num = 0; /* 不需要地址比较层的数量 */
	char cur_stack_streaminfo_more_array[__ADDR_TYPE_MAX] = {}; /* 栈里的流地址比堆里流地址层数多的地址类型标记 */

	while(phead!=NULL)
	{  
		pshead_pr=&(phead->stream);	
		/* 2015-12-14 lijia add, 先通过第二个HASH值预先判断是否相等, 如果HASH不同, 地址肯定不同 */
		if(pshead_pr->hash_slave != psinsert_pr->hash_slave){
			phead=phead->phashnext;
			hash_list_num++;
			continue;
		}
		result=checkstreamorder(&plinkhead->stream, pshead_pr,psinsert_pr, &heap_streaminfo_skip_layer_num, &stack_streaminfo_skip_layer_num);
		if(result==0){
			res = phead;
			break;
		}

		phead=phead->phashnext;
		hash_list_num++;
	}
	if(plinkhead->stream.stream_public.type == STREAM_TYPE_UDP)
	{
		if(unlikely(hash_list_num > local_sys_stat->count[SAPP_STAT_UDP_HASH_LIST_MAX])){
			local_sys_stat->count[SAPP_STAT_UDP_HASH_LIST_MAX] = hash_list_num;
		}
	}
	else if(plinkhead->stream.stream_public.type == STREAM_TYPE_TCP)
	{
		if(unlikely(hash_list_num > local_sys_stat->count[SAPP_STAT_TCP_HASH_LIST_MAX])){
			local_sys_stat->count[SAPP_STAT_TCP_HASH_LIST_MAX] = hash_list_num;
		}
	}

	if((res != NULL) && (stack_streaminfo_skip_layer_num > heap_streaminfo_skip_layer_num)){
		streaminfo_layer_alignment(&res->stream.stream_public, &res->stream, &pinsert->stream);
	}

	return res;
}




/*
//本函数内做了的事情
//1) 判定是否存在流
//2) 更新流的方向信息 ,dir ,curdir ,routdir
*/
struct streamindex *findstreamindex(struct streamindex *pindex, const raw_pkt_t *raw_pkt)
{
	struct streamindex **phashstream=NULL;
	struct streamindex *a_index=NULL;
	struct streaminfo_private *pstream_pr = &(pindex->stream);
	struct streaminfo *ptmp=&pstream_pr->stream_public;
	struct streaminfo *a_stream=NULL;
	UCHAR threadnum = ptmp->threadnum;
	UCHAR stream_type = ptmp->type;
	unsigned int hash_max;
	unsigned int hash_index;
	unsigned short elemcount=0;
	struct global_stream *this_thread_stream = G_MESA_GLOBAL_STREAM[threadnum];

	if (STREAM_TYPE_TCP== stream_type)
	{
		phashstream=this_thread_stream->tcp_stream_table;
		hash_max=tcp_stream_table_size;
	}	
	else if(STREAM_TYPE_UDP==stream_type)
	{
		phashstream=this_thread_stream->udp_stream_table;
		hash_max=udp_stream_table_size;
	}else{
         	phashstream = NULL;
         	hash_max = 0;
		assert(0);
         }

#if USE_LINUX_KERNEL_HASH_ALGO
	extern int stream_make_jhash(struct streaminfo_private *stream_pr, unsigned int maxsize);
	hash_index=stream_make_jhash(&(pindex->stream), (unsigned int)hash_max);
#else
	extern int stream_make_rte_crchash(struct streaminfo_private *stream_pr, unsigned int maxsize);
	hash_index=stream_make_rte_crchash(&(pindex->stream), (unsigned int)hash_max);
#endif

	if(STREAM_TYPE_UDP==stream_type)
	{
		elemcount=this_thread_stream->udp_stream_talbe_hash_count[hash_index];
	}
	else if (STREAM_TYPE_TCP==stream_type)
	{
		elemcount=this_thread_stream->tcp_stream_talbe_hash_count[hash_index];
	}

	if(0 == elemcount){ /* 2015-12-14 lijia add, HASH表当前SLOT并没有流, 直接返回 */
		ptmp->hash_index = hash_index; /* 保存计算得到的HASH值 */
		return NULL;
	}
	
	a_index = findandsethashindex_lru(phashstream[hash_index],pindex);

	if (likely(a_index!=NULL)){
	
		/*
			2015-12-14 lijia add
			NOTE: 
			如果当前流连续N次都不是HASH_SLOT的第一位, 则移动到第一位, 移动后计数清零,
			下次查找可能最优, 
			同时防止凑巧一个SLOT的几个流都频繁有包的情况下, 指针频繁来回移动, 甚至降低性能.

			目的是哪个流的数据包较多, 谁就经常在SLOT第一位.
		*/
		if((a_index != phashstream[hash_index]) && (a_index->stream.hash_not_head_times++ > 5)){ 
			if(a_index->phashnext){
				a_index->phashnext->phashprev = a_index->phashprev;
			}
			if(a_index->phashprev){
				a_index->phashprev->phashnext = a_index->phashnext;
			}
			
			   phashstream[hash_index]->phashprev=a_index;
			   a_index->phashnext=phashstream[hash_index];
			   phashstream[hash_index] = a_index;		
			   a_index->phashprev = NULL;
			   a_index->stream.hash_not_head_times = 0;
		}
			
		pstream_pr = &(a_index->stream);
 		a_stream=&(pstream_pr->stream_public);
		if(pstream_pr->stream_dir != 1)
		{
			if(ptmp->curdir==DIR_C2S)
				a_stream->curdir=DIR_S2C;
			else
				a_stream->curdir=DIR_C2S;
		}
		else
		{
			a_stream->curdir=ptmp->curdir;
		}
		a_stream->routedir=ptmp->routedir;
		
		return a_index;
	}
	else 
	{
		ptmp->hash_index=hash_index;
	}

	return NULL;
}


void hash_add_stream(struct streamindex *pindex)
{
	struct streamindex **phashstream;
	struct streaminfo_private *pstream_pr=&(pindex->stream);
	struct streaminfo *ptmp = &pstream_pr->stream_public;
	unsigned short *pelementcount;
	UCHAR threadnum = ptmp->threadnum;
	unsigned int hash_index = ptmp->hash_index;
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[threadnum]->sys_stat;

	if (STREAM_TYPE_TCP==ptmp->type)
	 {
          phashstream=G_MESA_GLOBAL_STREAM[threadnum]->tcp_stream_table;
 	 	  pelementcount=G_MESA_GLOBAL_STREAM[threadnum]->tcp_stream_talbe_hash_count;
 	 	  local_sys_stat->count[SAPP_STAT_TCP_STREAM_NEW]++;
	 }	
	else if(STREAM_TYPE_UDP==ptmp->type)
     {
        phashstream=G_MESA_GLOBAL_STREAM[threadnum]->udp_stream_table;
 	    pelementcount=G_MESA_GLOBAL_STREAM[threadnum]->udp_stream_talbe_hash_count;
		local_sys_stat->count[SAPP_STAT_UDP_STREAM_NEW]++;
     } else{
     	phashstream = NULL;
     	pelementcount = 0;
		assert(0);
     }
	 
	
	 /* 放在HASH-Slot第一个位置 */
	   if(phashstream[hash_index]!=NULL)
		phashstream[hash_index]->phashprev=pindex;
	   pindex->phashnext=phashstream[hash_index];
	   phashstream[hash_index] = pindex;

	pelementcount[hash_index]++;

	/* TCP, UDP新建流时都会调用此函数, 所以把ddos检测放到此处,
		但是切记不要放到streamaddlist()函数, 因为同一个流切换不同状态时, 可能会调用streamaddlist()好几次.
	*/
	if(pindex->stream.create_dir_by_well_known_port != 1)
	{
		pindex->stream.under_ddos_bypass = packet_io_under_ddos_should_bypass(threadnum);
	}

	pindex->stream.global_stream_id = get_global_stream_id(threadnum);
	pindex->stream.stream_trace_id=0;
}


void hash_del_stream(struct streamindex *pindex)
{
	struct streamindex **phashstream;
	struct streaminfo_private *pstream_pr=&(pindex->stream);
	struct streaminfo *ptmp = &pstream_pr->stream_public;	
	unsigned short *pelementcount;
	UCHAR threadnum = ptmp->threadnum;
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[threadnum]->sys_stat;

    if (STREAM_TYPE_UDP == ptmp->type)
    {
        phashstream = G_MESA_GLOBAL_STREAM[threadnum]->udp_stream_table;
        pelementcount = G_MESA_GLOBAL_STREAM[threadnum]->udp_stream_talbe_hash_count;
        local_sys_stat->count[SAPP_STAT_UDP_STREAM_DEL]++;
        if (ptmp->pudpdetail->clientpktnum + ptmp->pudpdetail->serverpktnum >=
                sapp_global_val->config.stream.udp.meaningful_statistics_minimum_pkt &&
            ptmp->pudpdetail->clientbytes + ptmp->pudpdetail->serverbytes >=
                sapp_global_val->config.stream.udp.meaningful_statistics_minimum_byte)
        {
            if (ptmp->dir == DIR_DOUBLE)
            {
                local_sys_stat->count[SAPP_STAT_UDP_STREAM_DOUBLE]++;
                local_sys_stat->count[SAPP_STAT_UDP_STREAM_DOUBLE_PKTS] +=
                    (ptmp->pudpdetail->clientpktnum + ptmp->pudpdetail->serverpktnum);
                local_sys_stat->count[SAPP_STAT_UDP_STREAM_DOUBLE_BYTES] +=
                    (ptmp->pudpdetail->clientbytes + ptmp->pudpdetail->serverbytes);
            }
            else if (ptmp->dir == DIR_C2S)
            {
                local_sys_stat->count[SAPP_STAT_UDP_STREAM_C2S]++;
                local_sys_stat->count[SAPP_STAT_UDP_STREAM_C2S_PKTS] +=
                    (ptmp->ptcpdetail->clientpktnum + ptmp->ptcpdetail->serverpktnum);
                local_sys_stat->count[SAPP_STAT_UDP_STREAM_C2S_BYTES] +=
                    (ptmp->ptcpdetail->clientbytes + ptmp->ptcpdetail->serverbytes);
            }
            else if (ptmp->dir == DIR_S2C)
            {
                local_sys_stat->count[SAPP_STAT_UDP_STREAM_S2C]++;
                local_sys_stat->count[SAPP_STAT_UDP_STREAM_S2C_PKTS] +=
                    (ptmp->ptcpdetail->clientpktnum + ptmp->ptcpdetail->serverpktnum);
                local_sys_stat->count[SAPP_STAT_UDP_STREAM_S2C_BYTES] +=
                    (ptmp->ptcpdetail->clientbytes + ptmp->ptcpdetail->serverbytes);
            }
        }
        if (ptmp->dir == DIR_DOUBLE)
        {
            local_sys_stat->count[SAPP_STAT_UDP_STREAM_TOTAL_DOUBLE]++;
            local_sys_stat->count[SAPP_STAT_UDP_STREAM_TOTAL_DOUBLE_PKTS] +=
                (ptmp->pudpdetail->clientpktnum + ptmp->pudpdetail->serverpktnum);
            local_sys_stat->count[SAPP_STAT_UDP_STREAM_TOTAL_DOUBLE_BYTES] +=
                (ptmp->pudpdetail->clientbytes + ptmp->pudpdetail->serverbytes);
        }
        else if (ptmp->dir == DIR_C2S)
        {
            local_sys_stat->count[SAPP_STAT_UDP_STREAM_TOTAL_C2S]++;
            local_sys_stat->count[SAPP_STAT_UDP_STREAM_TOTAL_C2S_PKTS] +=
                (ptmp->ptcpdetail->clientpktnum + ptmp->ptcpdetail->serverpktnum);
            local_sys_stat->count[SAPP_STAT_UDP_STREAM_TOTAL_C2S_BYTES] +=
                (ptmp->ptcpdetail->clientbytes + ptmp->ptcpdetail->serverbytes);
        }
        else if (ptmp->dir == DIR_S2C)
        {
            local_sys_stat->count[SAPP_STAT_UDP_STREAM_TOTAL_S2C]++;
            local_sys_stat->count[SAPP_STAT_UDP_STREAM_TOTAL_S2C_PKTS] +=
                (ptmp->ptcpdetail->clientpktnum + ptmp->ptcpdetail->serverpktnum);
            local_sys_stat->count[SAPP_STAT_UDP_STREAM_TOTAL_S2C_BYTES] +=
                (ptmp->ptcpdetail->clientbytes + ptmp->ptcpdetail->serverbytes);
        }
    }
    else if (STREAM_TYPE_TCP == ptmp->type)
    {
        const struct tcpdetail_private *pdetail_pr = (struct tcpdetail_private *)(ptmp->pdetail);
        phashstream = G_MESA_GLOBAL_STREAM[threadnum]->tcp_stream_table;
        pelementcount = G_MESA_GLOBAL_STREAM[threadnum]->tcp_stream_talbe_hash_count;
        local_sys_stat->count[SAPP_STAT_TCP_STREAM_DEL]++;

        if (pdetail_pr->has_lost_pkt_flag != 0)
        {
            local_sys_stat->count[SAPP_STAT_TCP_LOST_PKT_STREAM_NUM]++;
        }

        if (ptmp->ptcpdetail->clientpktnum + ptmp->ptcpdetail->serverpktnum >=
                sapp_global_val->config.stream.tcp.meaningful_statistics_minimum_pkt &&
            ptmp->ptcpdetail->clientbytes + ptmp->ptcpdetail->serverbytes >=
                sapp_global_val->config.stream.tcp.meaningful_statistics_minimum_byte)
        {
            if (ptmp->dir == DIR_DOUBLE)
            {
                local_sys_stat->count[SAPP_STAT_TCP_STREAM_DOUBLE]++;
                local_sys_stat->count[SAPP_STAT_TCP_STREAM_DOUBLE_PKTS] +=
                    (ptmp->ptcpdetail->clientpktnum + ptmp->ptcpdetail->serverpktnum);
                local_sys_stat->count[SAPP_STAT_TCP_STREAM_DOUBLE_BYTES] +=
                    (ptmp->ptcpdetail->clientbytes + ptmp->ptcpdetail->serverbytes);
            }
            else if (ptmp->dir == DIR_C2S)
            {
                local_sys_stat->count[SAPP_STAT_TCP_STREAM_C2S]++;
                local_sys_stat->count[SAPP_STAT_TCP_STREAM_C2S_PKTS] +=
                    (ptmp->ptcpdetail->clientpktnum + ptmp->ptcpdetail->serverpktnum);
                local_sys_stat->count[SAPP_STAT_TCP_STREAM_C2S_BYTES] +=
                    (ptmp->ptcpdetail->clientbytes + ptmp->ptcpdetail->serverbytes);
            }
            else if (ptmp->dir == DIR_S2C)
            {
                local_sys_stat->count[SAPP_STAT_TCP_STREAM_S2C]++;
                local_sys_stat->count[SAPP_STAT_TCP_STREAM_S2C_PKTS] +=
                    (ptmp->ptcpdetail->clientpktnum + ptmp->ptcpdetail->serverpktnum);
                local_sys_stat->count[SAPP_STAT_TCP_STREAM_S2C_BYTES] +=
                    (ptmp->ptcpdetail->clientbytes + ptmp->ptcpdetail->serverbytes);
            }
            else
                ;
        }

        if (ptmp->dir == DIR_DOUBLE)
        {
            local_sys_stat->count[SAPP_STAT_TCP_STREAM_TOTAL_DOUBLE]++;
            local_sys_stat->count[SAPP_STAT_TCP_STREAM_TOTAL_DOUBLE_PKTS] +=
                (ptmp->ptcpdetail->clientpktnum + ptmp->ptcpdetail->serverpktnum);
            local_sys_stat->count[SAPP_STAT_TCP_STREAM_TOTAL_DOUBLE_BYTES] +=
                (ptmp->ptcpdetail->clientbytes + ptmp->ptcpdetail->serverbytes);
        }
        else if (ptmp->dir == DIR_C2S)
        {
            local_sys_stat->count[SAPP_STAT_TCP_STREAM_TOTAL_C2S]++;
            local_sys_stat->count[SAPP_STAT_TCP_STREAM_TOTAL_C2S_PKTS] +=
                (ptmp->ptcpdetail->clientpktnum + ptmp->ptcpdetail->serverpktnum);
            local_sys_stat->count[SAPP_STAT_TCP_STREAM_TOTAL_C2S_BYTES] +=
                (ptmp->ptcpdetail->clientbytes + ptmp->ptcpdetail->serverbytes);
        }
        else if (ptmp->dir == DIR_S2C)
        {
            local_sys_stat->count[SAPP_STAT_TCP_STREAM_TOTAL_S2C]++;
            local_sys_stat->count[SAPP_STAT_TCP_STREAM_TOTAL_S2C_PKTS] +=
                (ptmp->ptcpdetail->clientpktnum + ptmp->ptcpdetail->serverpktnum);
            local_sys_stat->count[SAPP_STAT_TCP_STREAM_TOTAL_S2C_BYTES] +=
                (ptmp->ptcpdetail->clientbytes + ptmp->ptcpdetail->serverbytes);
        }
    }
    else
    {
        phashstream = NULL;
        pelementcount = 0;
        assert(0);
    }

    if (pindex->phashprev != NULL)
    {
        pindex->phashprev->phashnext = pindex->phashnext;
    }
    else
    {
        phashstream[ptmp->hash_index] = pindex->phashnext;
    }
    if(pindex->phashnext!=NULL)
	{
		pindex->phashnext->phashprev=pindex->phashprev;
	}

	pindex->phashnext=pindex->phashprev=NULL;

	pelementcount[ptmp->hash_index]--;
}


int show_stream_state(int threadcount)
{
	int i=0;
	int j=0;

	printf("\n");
	printf("\n\n-------------------------------tcp stream state---------------------------------------");
	for(i=0;i<MAX_TCP_STATE;i++)
	{
		switch(i)
		{
			case TCP_SYN_STATE:
				printf("\ntcp_syn:\t");
				break;
			case TCP_DATA_STATE:
				printf("\ntcp_data:\t");
				break;
			case TCP_NOUSE_STATE:
				printf("\ntcp_nouse:\t");
				break;
			default:
				break;
		}
				
		for(j=0;j<threadcount;j++)
		{
			printf("%d\t",G_MESA_GLOBAL_STREAM[j]->tcpList[i].cnt);
		}
		
	}	

	printf("\n\n-------------------------------udp stream state---------------------------------------");
	for(i=0;i<MAX_UDP_STATE;i++)
	{
		switch(i)
		{
			case UDP_ONE_STATE:
				printf("\nudp one state:\t");
				break;
			case UDP_TWO_STATE:
				printf("\nudp two state:\t");
				break;
			case UDP_MORE_STATE:
				printf("\nudp more state:\t");
				break;
			default:
				break;
		}
				
		for(j=0;j<threadcount;j++)
		{
			printf("%d\t",G_MESA_GLOBAL_STREAM[j]->udpList[i].cnt);
		}
	}

	printf("\n");

	return 0;

}

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))



int addr_dir_relation(void *addr, int addrtype)
{
	int relation = 0;
	switch(addrtype){
		case __ADDR_TYPE_IP_PAIR_V4:
		{
			struct layer_addr_ipv4 *ip4_addr = (struct layer_addr_ipv4 *)addr;
			relation = memcmp(&ip4_addr->saddr, &ip4_addr->daddr, sizeof(int)); 
		}
		break;

		case __ADDR_TYPE_IP_PAIR_V6:
		{
			struct layer_addr_ipv6 *ip6_addr = (struct layer_addr_ipv6 *)addr;
			relation = memcmp(ip6_addr->saddr, ip6_addr->daddr, 16);
		}
		break;
		
		case ADDR_TYPE_TCP:
		case ADDR_TYPE_UDP:
		{
			struct layer_addr_tcp *tcp_addr = (struct layer_addr_tcp *)addr;
			relation = memcmp(&tcp_addr->source, &tcp_addr->dest, sizeof(short));
		}	
		break;

		default:
			/* 其他地址类型无方向性特征, 默认为0 */
			 relation = 0;
		break;
	}

	return relation;
}

/* 将addr地址反向 */
void reverse_addr(void *addr, int addrtype)
{
	UINT16 tmp_ushort;
	UINT32 tmp_uint;
	
	switch(addrtype){
		case ADDR_TYPE_IPV4:
		{
			struct layer_addr_ipv4 *ip4_addr = (struct layer_addr_ipv4 *)addr;
			tmp_uint = ip4_addr->saddr;
			ip4_addr->saddr = ip4_addr->daddr;
			ip4_addr->daddr = tmp_uint;
			tmp_ushort = ip4_addr->source;
			ip4_addr->source =  ip4_addr->dest;
			ip4_addr->dest = tmp_ushort;
		}
		break;

		case __ADDR_TYPE_IP_PAIR_V4:
		{
			struct layer_addr_ipv4 *ip4_pure_addr = (struct layer_addr_ipv4 *)addr;
			tmp_uint = ip4_pure_addr->saddr;
			ip4_pure_addr->saddr = ip4_pure_addr->daddr;
			ip4_pure_addr->daddr = tmp_uint;
		}		
		break;

		case ADDR_TYPE_IPV6:
		{
			struct layer_addr_ipv6 *ip6_addr = (struct layer_addr_ipv6 *)addr;
			UCHAR tmp[16]; 
			memcpy(tmp, ip6_addr->saddr, IPV6_ADDR_LEN);
			memcpy(ip6_addr->saddr, ip6_addr->daddr, IPV6_ADDR_LEN);
			memcpy(ip6_addr->daddr, tmp, IPV6_ADDR_LEN);
			tmp_ushort = ip6_addr->source;
			ip6_addr->source =  ip6_addr->dest;
			ip6_addr->dest = tmp_ushort;
		}
		break;

		case __ADDR_TYPE_IP_PAIR_V6:
		{
			struct layer_addr_ipv6 *ip6_pure_addr = (struct layer_addr_ipv6 *)addr;
			UCHAR tmp[16]; 
			memcpy(tmp, ip6_pure_addr->saddr, IPV6_ADDR_LEN);
			memcpy(ip6_pure_addr->saddr, ip6_pure_addr->daddr, IPV6_ADDR_LEN);
			memcpy(ip6_pure_addr->daddr, tmp, IPV6_ADDR_LEN);
		}
		break;
		
		case ADDR_TYPE_TCP:
		case ADDR_TYPE_UDP:
		{
			struct layer_addr_tcp *tcp_addr = (struct layer_addr_tcp *)addr;
			tmp_ushort = tcp_addr->source;
			tcp_addr->source =  tcp_addr->dest;
			tcp_addr->dest = tmp_ushort;
		}	
		break;

		/* TODO 1:PPTP-addr */

		default:
			/* 其他地址类型, 如VLAN, L2TP等, 无方向性特征, 无需转换 */
			return;
	}

	return;
}

/* 反向地址copy */
void addr_reverse_memcpy(const struct streaminfo_private *stack_stream_pr, void *daddr, const void *saddr, int addrtype, int addrlen)
{
	switch(addrtype){
		case ADDR_TYPE_IPV4:
		{
			const struct layer_addr_ipv4 *ip4_saddr = (const struct layer_addr_ipv4 *)saddr;
			struct layer_addr_ipv4 *ip4_daddr = (struct layer_addr_ipv4 *)daddr;
			ip4_daddr->saddr = ip4_saddr->daddr;
			ip4_daddr->daddr = ip4_saddr->saddr;		
			ip4_daddr->source = ip4_saddr->dest;
			ip4_daddr->dest = ip4_saddr->source;			
		}
		break;

		case ADDR_TYPE_IPV6:
		{
			const struct layer_addr_ipv6 *ip6_saddr = (const struct layer_addr_ipv6 *)saddr;
			struct layer_addr_ipv6 *ip6_daddr = (struct layer_addr_ipv6 *)daddr;
			memcpy(ip6_daddr->saddr, ip6_saddr->daddr, IPV6_ADDR_LEN);
			memcpy(ip6_daddr->daddr, ip6_saddr->saddr, IPV6_ADDR_LEN);
			ip6_daddr->source = ip6_saddr->dest;
			ip6_daddr->dest = ip6_saddr->source;	
		}
		break;

		case ADDR_TYPE_MAC: /* 2015-06-15 lijia add, 木马检测设备需求 */
		{
			const struct layer_addr_mac *cur_stack_mac_saddr = (const struct layer_addr_mac *) saddr;
			struct layer_addr_mac *heap_stream_mac_daddr = (struct layer_addr_mac *) daddr;
				
			//if (1 == sapp_global_val->config.protocol_feature.reverse_ethernet_addr_enabled) //2018-12-07 yw add, mac地址中包含信息时无需翻转
			if(g_asymmetric_addr_layer_set.layer_type_index[ADDR_TYPE_MAC][stack_stream_pr->layer_index] == 0){
				/* 不开启非对称地址特性时, ethernet和ip,tcp一样, 颠倒源和目的地址即可,双向地址都存储于src_addr */
				memcpy(heap_stream_mac_daddr->src_addr.h_source, cur_stack_mac_saddr->src_addr.h_dest, ETH_ALEN);
				memcpy(heap_stream_mac_daddr->src_addr.h_dest, cur_stack_mac_saddr->src_addr.h_source, ETH_ALEN);
			}else{
				/* 开启非对称地址特性时,两个方向各有四个mac地址,此时要整体copy 14个字节, 将栈中的src_addr存于heap的dst_addr中, 对于struct ethhdr中的地址方向不能变 */
				memcpy(&heap_stream_mac_daddr->dst_addr, &cur_stack_mac_saddr->src_addr, sizeof(struct ethhdr));
			}
		}
		break;

		case __ADDR_TYPE_IP_PAIR_V4: /* 纯IPv4层, 通常是基于隧道模式 */
		{
			const struct layer_addr_ipv4 *ip4_saddr = (const struct layer_addr_ipv4 *)saddr;
			struct layer_addr_ipv4 *ip4_daddr = (struct layer_addr_ipv4 *)daddr;
			ip4_daddr->saddr = ip4_saddr->daddr;
			ip4_daddr->daddr = ip4_saddr->saddr;	 /* 只有IP地址 */	
			/* Note: 纯IP层的端口值一定要置为0, 否则会使用未初始化的内存, 在后续流还原的cmpaddr()函数中, 可能会导致流比较地址不一样而找不到 */
			ip4_daddr->source = 0;
			ip4_daddr->dest = 0;
		}		
		break;

		case __ADDR_TYPE_IP_PAIR_V6: /* 纯IPv6层, 通常是基于隧道模式 */
		{
			const struct layer_addr_ipv6 *ip6_saddr = (const struct layer_addr_ipv6 *)saddr;
			struct layer_addr_ipv6 *ip6_daddr = (struct layer_addr_ipv6 *)daddr;
			memcpy(ip6_daddr->saddr, ip6_saddr->daddr, IPV6_ADDR_LEN);
			memcpy(ip6_daddr->daddr, ip6_saddr->saddr, IPV6_ADDR_LEN);
			/* Note: 纯IP层的端口值一定要置为0, 否则会使用未初始化的内存, 在后续流还原的cmpaddr()函数中, 可能会导致流比较地址不一样而找不到 */
			ip6_daddr->source = 0;
			ip6_daddr->dest = 0;
		}		
		break;

        case ADDR_TYPE_VLAN:
        {
            const struct layer_addr_vlan *src_vlan = (const struct layer_addr_vlan *)saddr;
            struct layer_addr_vlan *dst_vlan = (struct layer_addr_vlan *)daddr;

            memset(dst_vlan, 0, sizeof(struct layer_addr_vlan));
			/* 当前stack里的包地址信息固定存储于src方向, 反向copy是将stack地址拷贝到堆里的地址 */
            memcpy(dst_vlan->s2c_addr_array, src_vlan->c2s_addr_array, sizeof(src_vlan->c2s_addr_array));
            dst_vlan->s2c_layer_num = src_vlan->c2s_layer_num;
        }
        break;

		case ADDR_TYPE_GPRS_TUNNEL:
		{
			const struct layer_addr_gtp *src_gtp = (const struct layer_addr_gtp *)saddr;
			struct layer_addr_gtp *dst_gtp = (struct layer_addr_gtp *)daddr;

			dst_gtp->teid_s2c = src_gtp->teid_c2s;
		}
		break;

        case ADDR_TYPE_MPLS:
        {
            const struct layer_addr_mpls *current_stack_addr = (const struct layer_addr_mpls *)saddr;
            struct layer_addr_mpls *dst_mpls = (struct layer_addr_mpls *)daddr;

            memset(dst_mpls, 0, sizeof(struct layer_addr_mpls));
			/* 当前stack里的包地址信息固定存储于src方向, 反向copy是将stack地址拷贝到堆里的地址 */
            memcpy(dst_mpls->s2c_addr_array, current_stack_addr->c2s_addr_array, sizeof(current_stack_addr->c2s_addr_array));
            dst_mpls->s2c_layer_num = current_stack_addr->c2s_layer_num;
            if(current_stack_addr->c2s_has_ctrl_word){
            	dst_mpls->s2c_mpls_ctrl_word = current_stack_addr->c2s_mpls_ctrl_word;
				dst_mpls->s2c_has_ctrl_word = 1;
            }
        }
        break;
        
		case ADDR_TYPE_PPTP:
		{
			const struct layer_addr_pptp *pptp_saddr = (const struct layer_addr_pptp *)saddr;
			struct layer_addr_pptp *pptp_daddr = (struct layer_addr_pptp *)daddr;
			pptp_daddr->C2S_call_id = pptp_saddr->C2S_call_id;
			pptp_daddr->S2C_call_id = pptp_saddr->S2C_call_id;
		}
		break;

		case ADDR_TYPE_L2TP:
		{
			const struct layer_addr_l2tp *src_l2tp = (const struct layer_addr_l2tp *)saddr;
			struct layer_addr_l2tp *dst_l2tp = (struct layer_addr_l2tp *)daddr;

			memcpy(dst_l2tp, src_l2tp, sizeof(struct layer_addr_l2tp));
			dst_l2tp->l2tpun.l2tp_addr_v2.tunnelid_S2C = dst_l2tp->l2tpun.l2tp_addr_v2.tunnelid_C2S;
			dst_l2tp->l2tpun.l2tp_addr_v2.sessionid_S2C = dst_l2tp->l2tpun.l2tp_addr_v2.sessionid_C2S;

			dst_l2tp->l2tpun.l2tp_addr_v2.seq_present_S2C = dst_l2tp->l2tpun.l2tp_addr_v2.seq_present_C2S;
		}
		break;
		
		default:
			/* 其他地址类型, 无方向性特征,直接copy */
			memcpy(daddr, saddr, addrlen);
			return;
	}

	return;
}

/* 
	因为预先分配了一些streamindex结构, 每次创建流时, 从预先分配的内存中获取,  
	但malloc_and_copy_streamindex()函数, 只copy streamindex结构, 没有addr.paddr, 
	需要将地址信息也copy到堆里.
*/
int copy_ipport_union_addr(struct streaminfo *pstream_heap, struct streaminfo *pstream_stack, int reverse)
{
	pstream_heap->addr.paddr = sapp_mem_malloc(SAPP_MEM_DYN_PADDR, pstream_stack->threadnum, pstream_stack->addr.addrlen);
	if(0 == reverse){
		memcpy(pstream_heap->addr.paddr, pstream_stack->addr.paddr, pstream_stack->addr.addrlen);
	}else{
		addr_reverse_memcpy((const struct streaminfo_private *)pstream_stack, pstream_heap->addr.paddr, pstream_stack->addr.paddr, pstream_stack->addr.addrtype, pstream_stack->addr.addrlen);
	}
	
	return 0;
}


void free_thread_stream(int thread_seq)
{
	struct global_stream *g_stream;
	struct stream_list *plist;
	struct streamindex *pindex;
	int j;
	int all_done = 0;
	struct timeout *t = NULL;
	struct timeouts_it it_all;
	
	  g_stream=G_MESA_GLOBAL_STREAM[thread_seq];
	  timeouts_close(g_stream->user_define_timer);
	  for(j=0;j<MAX_TCP_STATE;j++)
	 {
	 	plist=&(g_stream->tcpList[j]);
		sapp_runtime_log(RLOG_LV_INFO, "free_thread_stream thread:%d, TCP_STATE[%d], timer_count:%d, current state:%d!", thread_seq, j , plist->cnt, sapp_get_current_state());
		TIMEOUTS_IT_INIT(&it_all, TIMEOUTS_ALL);
		all_done=0;
		while(!all_done)
		{
			t = timeouts_next(plist->streamindex_timer, &it_all);
			if(t)
			{
				pindex = container_of(t, struct streamindex, timeout);
				del_stream(pindex, STREAM_CLOSE_REASON_DUMPFILE);
			}
			else
			{
				all_done = 1;
			}
		}
		timeouts_close(plist->streamindex_timer);
	  }	
  	  for(j=0;j<MAX_UDP_STATE;j++)
	 {
	 	plist=&(g_stream->udpList[j]);
		sapp_runtime_log(RLOG_LV_INFO, "free_thread_stream thread:%d, UDP_STATE[%d], timer_count:%d, current state:%d!", thread_seq, j ,plist->cnt, sapp_get_current_state());
		all_done=0;
		TIMEOUTS_IT_INIT(&it_all, TIMEOUTS_ALL);
		while(!all_done)
		{
			t = timeouts_next(plist->streamindex_timer, &it_all);
			if(t)
			{
				pindex = container_of(t, struct streamindex, timeout);
				del_stream(pindex, STREAM_CLOSE_REASON_DUMPFILE);
			}
			else
			{
				all_done = 1;
			}
		}
		timeouts_close(plist->streamindex_timer);
	  }

}

/* 2014-04-08 LiJia add */
void free_heap_stream_info(int mem_used_type, struct streaminfo *heap_stream, int layer)
{
	struct streaminfo_private *heap_stream_pr = (struct streaminfo_private *)(heap_stream);
	struct streaminfo_private *pfather_pr;
	struct layer_addr *addr;

	if(NULL == heap_stream){
		return;
	}

	pfather_pr = heap_stream_pr->pfather_pr;
	addr = &heap_stream->addr;

	/* 为了节省空间, 地址类型ADDR_TYPE_IPV4/6实际存储在下一层的IP层, 无需free */
	if(addr->paddr){
		sapp_mem_free(SAPP_MEM_DYN_PADDR, heap_stream->threadnum, addr->paddr);
		addr->paddr = NULL;
	}
	
	if(layer != 0){
		/* 流结构的最内层即第0层, 实际是通过malloc_and_copy_streamindex()获取的预先分配的内存,
			无需free, 
			pfather指向的streaminfo结构才是通过copy_stream_info_to_heap()动态malloc的.
		*/
		sapp_mem_free((sapp_mem_type_t)mem_used_type, heap_stream->threadnum, heap_stream);	
	}
	return free_heap_stream_info(mem_used_type, (struct streaminfo *)pfather_pr, layer+1);
}

/* 2014-12-03 lijia add for sysinfo.log 
	args:
		action: 1:add; -1:del;
*/
static inline void update_stream_status(UCHAR threadnum, UCHAR stream_type, UCHAR stream_state,  int action)
{
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[threadnum]->sys_stat;
	

	if(STREAM_TYPE_TCP == stream_type){
		switch(stream_state)
		{
			case TCP_DATA_STATE:
					local_sys_stat->count[SAPP_STAT_TCP_STREAM_DATA] += action;
					break;
			case TCP_NOUSE_STATE:
					local_sys_stat->count[SAPP_STAT_TCP_STREAM_NOUSE] += action;
					break;
			case TCP_SYN_STATE:
					local_sys_stat->count[SAPP_STAT_TCP_STREAM_SYN] += action;
					break;					
		}	
	}else if(STREAM_TYPE_UDP == stream_type){
		switch(stream_state)
		{
			case UDP_TWO_STATE:
					local_sys_stat->count[SAPP_STAT_UDP_STREAM_TWO] += action;
					break;
			case UDP_MORE_STATE:
					local_sys_stat->count[SAPP_STAT_UDP_STREAM_MORE] += action;
					break;
			case UDP_ONE_STATE:
					local_sys_stat->count[SAPP_STAT_UDP_STREAM_ONE] += action;
					break;
		}			
	}
}


/*
	因众核tilera架构下的内存分配分为local和shared模式, 
	原来在主线程将所有全局内存一次性申请完的模式不可用, 
	改为每个工作线程自己初始化.
*/
int thread_self_init(int thread_seq)
{
	return 0;
}


int get_stream_carry_tunnel_type(const struct streaminfo *this_stream, 
                         const struct streaminfo *upper_stream, unsigned short *tunnel_type)
{
	if(NULL == this_stream){
		return 0;
	}

	if(NULL == upper_stream){
		*tunnel_type = STREAM_TUNNLE_NON;
	}
	
	/* 父流的指针, 注意: sapp_online版和sapp_ip_port_union版不一致 */
	const struct streaminfo *pfather = this_stream->pfather; 
	
	switch(this_stream->addr.addrtype){
		case ADDR_TYPE_MAC:
			pfather = this_stream->pfather;  //
			if(pfather != NULL){
					//mac in mac不算做隧道, 只是一种overlay的方式.
			}
			break;

		case ADDR_TYPE_IPV4:
			pfather = this_stream->pfather;  /* IP-TCP/UDP被认为是一个整体, 更新pfather指针 */
			if(pfather != NULL){
				 if(__ADDR_TYPE_IP_PAIR_V4 == pfather->addr.addrtype){
				 	*tunnel_type |= (unsigned short)STREAM_TUNNLE_IP_IN_IP;
				 }else if(__ADDR_TYPE_IP_PAIR_V6 == pfather->addr.addrtype){
					*tunnel_type |= (unsigned short)STREAM_TUNNLE_4OVER6;
				 }else if(ADDR_TYPE_GRE == pfather->addr.addrtype){
				 	*tunnel_type |= (unsigned short)STREAM_TUNNLE_GRE;
				 }
			} 
		break;

		case __ADDR_TYPE_IP_PAIR_V4:
			if(pfather != NULL){
				 if(__ADDR_TYPE_IP_PAIR_V6 == pfather->addr.addrtype){
				 	*tunnel_type |= (unsigned short)STREAM_TUNNLE_4OVER6;
				 }				
			}		
		break;

		case __ADDR_TYPE_IP_PAIR_V6:
			if(pfather != NULL){
				 if(__ADDR_TYPE_IP_PAIR_V4 == pfather->addr.addrtype){
				 	*tunnel_type |= (unsigned short)STREAM_TUNNLE_6OVER4;
				 }				
			}
		break;		
		
		case ADDR_TYPE_IPV6:
			pfather = this_stream->pfather;  /* IP-TCP/UDP被认为是一个整体, 更新pfather指针 */
			if(pfather != NULL){
				if(__ADDR_TYPE_IP_PAIR_V4 == pfather->addr.addrtype){
					*tunnel_type |= (unsigned short)STREAM_TUNNLE_6OVER4;
				}else if((ADDR_TYPE_IPV4 == pfather->addr.addrtype)
				 && (STREAM_TYPE_UDP == pfather->type)){
					*tunnel_type |= (unsigned short)STREAM_TUNNLE_TEREDO;
				}else if(ADDR_TYPE_GRE == pfather->addr.addrtype){
				 	*tunnel_type |= (unsigned short)STREAM_TUNNLE_GRE;
				 }
			}
		break;

		case ADDR_TYPE_GRE:
			if((ADDR_TYPE_IPV4 == upper_stream->addr.addrtype)
			||((ADDR_TYPE_IPV6 == upper_stream->addr.addrtype))
			||(__ADDR_TYPE_IP_PAIR_V4 == upper_stream->addr.addrtype)
			||(__ADDR_TYPE_IP_PAIR_V6 == upper_stream->addr.addrtype)){
				*tunnel_type |= (unsigned short)STREAM_TUNNLE_GRE;
			}
		break;

		case ADDR_TYPE_PPTP:
			/* pptp_entry()函数中已经将地址重置为ADDR_TYPE_PPTP, 肯定就是PPTP隧道 */
			*tunnel_type |= (unsigned short)STREAM_TUNNLE_PPTP;
		break;

		case ADDR_TYPE_L2TP:
			/* l2tp_entry()函数中已经将地址重置为ADDR_TYPE_L2TP, 肯定就是L2TP隧道 */
			*tunnel_type |= (unsigned short)STREAM_TUNNLE_L2TP;
		break;

		case ADDR_TYPE_GPRS_TUNNEL:
			/* gtp_entry()函数中已经将地址重置为ADDR_TYPE_GTP, 肯定就是GTP隧道 */
			*tunnel_type |= (unsigned short)STREAM_TUNNEL_GPRS_TUNNEL;
			break;
	}

	/* 2021-01-11, 此处可以不关心vxlan等封装层, 直接用pfather */
	return get_stream_carry_tunnel_type(pfather, this_stream, tunnel_type);
}


void update_opposite_addr_info(struct streaminfo_private *top_stream_pr, struct streaminfo_private *pstream_pr, 
	struct streaminfo_private *p_stack, unsigned char cur_dir)
{
	if(pstream_pr == NULL || p_stack == NULL)
	{
		return;
	}
	
	if(p_stack->need_update_opposite_addr != 0) {
		switch(p_stack->stream_public.addr.addrtype)
		{
			case ADDR_TYPE_GPRS_TUNNEL:
			    /* GTP地址C2S, S2C方向独立, 无法靠当前包地址区分dir, 每次栈里的变量都存储于source方向, 即C2S方向,  
			       创建流时, 已经根据最内层TCP, UDP的流方向, 将GTP的地址存于source或dest, 
			       此函数是更新的对端缺失的地址, 仅靠最内层的cur_dir表示需要更新哪个方向的地址, 固定从当前包p_stack的source拷贝. 
			     */
				if(cur_dir == DIR_C2S){
                    pstream_pr->stream_public.addr.gtp->teid_c2s = p_stack->stream_public.addr.gtp->teid_c2s;/* 注意: 此处不是笔误, 就是C2S */
				}
				else{
                    pstream_pr->stream_public.addr.gtp->teid_s2c = p_stack->stream_public.addr.gtp->teid_c2s;/* 注意: 此处不是笔误, 就是C2S */
				}
				break;
				
			case ADDR_TYPE_MPLS:
				if(ADDR_TYPE_MPLS == pstream_pr->stream_public.addr.addrtype){
					if(cur_dir == DIR_C2S){
						memcpy(pstream_pr->stream_public.addr.mpls->c2s_addr_array,
						        p_stack->stream_public.addr.mpls->c2s_addr_array,
						        sizeof(p_stack->stream_public.addr.mpls->c2s_addr_array));
	                    pstream_pr->stream_public.addr.mpls->c2s_layer_num = p_stack->stream_public.addr.mpls->c2s_layer_num;
	                    if(p_stack->stream_public.addr.mpls->c2s_has_ctrl_word){//注意, 这里固定判断src方向!!
							pstream_pr->stream_public.addr.mpls->c2s_mpls_ctrl_word = p_stack->stream_public.addr.mpls->c2s_mpls_ctrl_word;
							pstream_pr->stream_public.addr.mpls->c2s_has_ctrl_word = 1;
	                    }
	                    //if(p_stack->fake_layer_dir_for_asymmetric_cmp != 0){
						//	pstream_pr->fake_layer_dir_for_asymmetric_cmp |= DIR_C2S;
	                    //}
					}
					else{
	                    memcpy(pstream_pr->stream_public.addr.mpls->s2c_addr_array,
	                           p_stack->stream_public.addr.mpls->c2s_addr_array,
	                           sizeof(p_stack->stream_public.addr.mpls->c2s_addr_array));
	                    pstream_pr->stream_public.addr.mpls->s2c_layer_num = p_stack->stream_public.addr.mpls->c2s_layer_num;
	                    if(p_stack->stream_public.addr.mpls->c2s_has_ctrl_word){ //注意, 这里固定判断src方向!!
							pstream_pr->stream_public.addr.mpls->s2c_mpls_ctrl_word = p_stack->stream_public.addr.mpls->c2s_mpls_ctrl_word;
							pstream_pr->stream_public.addr.mpls->s2c_has_ctrl_word = 1;
	                    }	 
	                    //if(p_stack->fake_layer_dir_for_asymmetric_cmp != 0){
						//	pstream_pr->fake_layer_dir_for_asymmetric_cmp |= DIR_S2C;
	                    //}     
					}
				}else{
					sapp_runtime_log(RLOG_LV_INFO, "update_opposite_addr_info() error, current addrtype is mpls, but pstream->addrtype is not mpls!");
				}
				break;
				
			case ADDR_TYPE_VLAN:
				if(ADDR_TYPE_VLAN == pstream_pr->stream_public.addr.addrtype){
					if(cur_dir == DIR_C2S){
						memcpy(pstream_pr->stream_public.addr.vlan->c2s_addr_array,
						        p_stack->stream_public.addr.vlan->c2s_addr_array,
						        sizeof(p_stack->stream_public.addr.vlan->c2s_addr_array));
	                    pstream_pr->stream_public.addr.vlan->c2s_layer_num = p_stack->stream_public.addr.vlan->c2s_layer_num;
					}
					else{
	                    memcpy(pstream_pr->stream_public.addr.vlan->s2c_addr_array,
	                           p_stack->stream_public.addr.vlan->c2s_addr_array,  //注意, 这里固定用src方向!!
	                           sizeof(p_stack->stream_public.addr.vlan->s2c_addr_array));
	                    pstream_pr->stream_public.addr.vlan->s2c_layer_num = p_stack->stream_public.addr.vlan->c2s_layer_num;    //注意, 这里固定用src方向!!                 
					}
				}else{
					sapp_runtime_log(RLOG_LV_INFO, "update_opposite_addr_info() error, current addrtype is vlan, but pstream->addrtype is not vlan!");
				}
			break;

			case ADDR_TYPE_MAC:
				if(g_asymmetric_addr_layer_set.layer_type_index[ADDR_TYPE_MAC][p_stack->layer_index] != 0){
					if(ADDR_TYPE_MAC == pstream_pr->stream_public.addr.addrtype){
						if(cur_dir == DIR_C2S){
							memcpy(&pstream_pr->stream_public.addr.mac->src_addr,
							        &p_stack->stream_public.addr.mac->src_addr,
							        sizeof(struct ethhdr));
						}
						else{
		                    memcpy(&pstream_pr->stream_public.addr.mac->dst_addr,
		                           &p_stack->stream_public.addr.mac->src_addr,  //注意, 这里固定用src方向!!
		                           sizeof(struct ethhdr));
						}
					}else{
						/* 继续在堆上streaminfo结构上查找 */
						return update_opposite_addr_info(top_stream_pr, (struct streaminfo_private *) pstream_pr->pfather_pr,
													(struct streaminfo_private *) p_stack, cur_dir);	
					}
				}
			break;

			case ADDR_TYPE_L2TP:
			{
				const struct layer_addr_l2tp *p_stack_addr = p_stack->stream_public.addr.l2tp;
				struct layer_addr_l2tp *p_stream_addr = pstream_pr->stream_public.addr.l2tp;
				
			    /* L2TP地址C2S, S2C方向独立, 无法靠当前包地址区分dir, 每次栈里的变量都存储于source方向, 即C2S方向,  
			       创建流时, 已经根据最内层TCP, UDP的流方向, 将GTP的地址存于source或dest, 
			       此函数是更新的对端缺失的地址, 仅靠最内层的cur_dir表示需要更新哪个方向的地址, 固定从当前包p_stack的source拷贝. 
			     */
				if(cur_dir == DIR_C2S){
                    p_stream_addr->l2tpun.l2tp_addr_v2.tunnelid_C2S = p_stack_addr->l2tpun.l2tp_addr_v2.tunnelid_C2S;
                    p_stream_addr->l2tpun.l2tp_addr_v2.sessionid_C2S = p_stack_addr->l2tpun.l2tp_addr_v2.sessionid_C2S;
                    p_stream_addr->l2tpun.l2tp_addr_v2.seq_present_C2S = p_stack_addr->l2tpun.l2tp_addr_v2.seq_present_C2S;
				}else{
                    p_stream_addr->l2tpun.l2tp_addr_v2.tunnelid_S2C = p_stack_addr->l2tpun.l2tp_addr_v2.tunnelid_C2S; /* 注意: 此处不是笔误, 就是C2S */
                    p_stream_addr->l2tpun.l2tp_addr_v2.sessionid_S2C = p_stack_addr->l2tpun.l2tp_addr_v2.sessionid_C2S; /* 注意: 此处不是笔误, 就是C2S */
                    p_stream_addr->l2tpun.l2tp_addr_v2.seq_present_S2C = p_stack_addr->l2tpun.l2tp_addr_v2.seq_present_C2S;
				}
			}
			break;

			case ADDR_TYPE_VXLAN:
			{
				if(ADDR_TYPE_VXLAN == pstream_pr->stream_public.addr.addrtype){
					if(cur_dir == DIR_C2S){
						memcpy(&pstream_pr->stream_public.addr.vxlan->C2S_vxlan_addr,
						        &p_stack->stream_public.addr.vxlan->C2S_vxlan_addr,
						        sizeof(p_stack->stream_public.addr.vxlan->C2S_vxlan_addr));
					}
					else{
	                    memcpy(&pstream_pr->stream_public.addr.vxlan->S2C_vxlan_addr,
	                           &p_stack->stream_public.addr.vxlan->C2S_vxlan_addr,  //注意, 这里固定用src方向!!
	                           sizeof(p_stack->stream_public.addr.vxlan->S2C_vxlan_addr));             
					}
				}else{
					sapp_runtime_log(RLOG_LV_INFO, "update_opposite_addr_info() error, current addrtype is vxlan, but pstream->addrtype is not vxlan!");
				}

			}
			break;

			default:	
				/* 其他协议层不涉及C2S, S2C两个方向地址非对称问题 */
				break;
		}
	}
	
	return update_opposite_addr_info(top_stream_pr, (struct streaminfo_private *) pstream_pr->pfather_pr,
								 (struct streaminfo_private *) p_stack->pfather_pr, cur_dir);	
}


static inline raw_pkt_t *sapp_raw_pkt_dup(int mem_used_type, int thread_index, const raw_pkt_t *raw_pkt)
{
	int hdr_offset;
	
	raw_pkt_t *new_raw_pkt = (raw_pkt_t *)sapp_mem_malloc((sapp_mem_type_t)mem_used_type, thread_index, sizeof(raw_pkt_t));
	memcpy(new_raw_pkt, raw_pkt, sizeof(raw_pkt_t));
	
	new_raw_pkt->__lib_raw_pkt_data = sapp_mem_malloc((sapp_mem_type_t)mem_used_type, thread_index, raw_pkt->__lib_raw_pkt_len);
	memcpy((void *)(new_raw_pkt->__lib_raw_pkt_data), raw_pkt->__lib_raw_pkt_data, raw_pkt->__lib_raw_pkt_len);
	
	/* 更新raw_pkt_data指针 */
	hdr_offset = (char *)raw_pkt->raw_pkt_data - (char *)raw_pkt->__lib_raw_pkt_data;
	assert(hdr_offset <= 2048);	
	new_raw_pkt->raw_pkt_data = (char *)new_raw_pkt->__lib_raw_pkt_data + hdr_offset;
	return new_raw_pkt;
}


int update_polling_inject_context(int mem_used_type,struct streaminfo_private *pstream_pr, const raw_pkt_t *raw_pkt)
{
	int thread_index;

	if(0 == sapp_global_val->config.packet_io.polling_enabled){
		return 0;
	}

	if(pstream_pr->polling_inject_context==NULL)
	{
		return 0;
	}

	thread_index = pstream_pr->stream_public.threadnum;
	/* 保存当前流C2S, S2C方向的第一个包 */
	if((DIR_ROUTE_DOWN & pstream_pr->stream_public.routedir) == DIR_ROUTE_DOWN){
		if(NULL == pstream_pr->polling_inject_context->raw_pkt_down){
			pstream_pr->polling_inject_context->raw_pkt_down = sapp_raw_pkt_dup(mem_used_type,thread_index, raw_pkt);
			pstream_pr->polling_inject_context->meta[1] = dl_io_fun_list.dl_io_get1_rawpkt_meta(raw_pkt, thread_index);
		}
	}else{
		if(NULL == pstream_pr->polling_inject_context->raw_pkt_up){
			pstream_pr->polling_inject_context->raw_pkt_up = sapp_raw_pkt_dup(mem_used_type,thread_index, raw_pkt);
			pstream_pr->polling_inject_context->meta[0] = dl_io_fun_list.dl_io_get1_rawpkt_meta(raw_pkt, thread_index);
		}
	}

	return 0;
}

int save_polling_inject_context(int mem_used_type, struct streaminfo_private *pstream_pr, const raw_pkt_t *raw_pkt)
{
	int thread_index;

	if(0 == sapp_global_val->config.packet_io.polling_enabled){
		return 0;
	}

	thread_index = pstream_pr->stream_public.threadnum;

	pstream_pr->polling_inject_context = (polling_inject_context_t *)sapp_mem_malloc((sapp_mem_type_t)mem_used_type, thread_index, sizeof(polling_inject_context_t));
	memset(pstream_pr->polling_inject_context, 0, sizeof(polling_inject_context_t));

	/* TODO:
	    此处将每个方向的第一个包都存下来, 如果都是短流太费内存了, 也耗CPU,
	    如果遇到flood攻击就更严重了!!
	    将发包所需的参数都藏于private结构中, 不再依赖原始包 */
	if((DIR_ROUTE_DOWN & pstream_pr->stream_public.routedir) == DIR_ROUTE_DOWN){
		pstream_pr->polling_inject_context->raw_pkt_down = sapp_raw_pkt_dup(mem_used_type, thread_index, raw_pkt);
		pstream_pr->polling_inject_context->meta[1] = dl_io_fun_list.dl_io_get1_rawpkt_meta(raw_pkt, thread_index);
	}else{
		pstream_pr->polling_inject_context->raw_pkt_up = sapp_raw_pkt_dup(mem_used_type, thread_index, raw_pkt);
		pstream_pr->polling_inject_context->meta[0] = dl_io_fun_list.dl_io_get1_rawpkt_meta(raw_pkt, thread_index);
	}

	return 0;
}

static inline void sapp_raw_pkt_free(int mem_used_type, int thread_index, raw_pkt_t *raw_pkt)
{
	sapp_mem_free((sapp_mem_type_t)mem_used_type, thread_index, (void *)raw_pkt->__lib_raw_pkt_data);
	sapp_mem_free((sapp_mem_type_t)mem_used_type, thread_index, (void *)raw_pkt);
}

void free_polling_inject_context(int mem_used_type, struct streaminfo_private *pstream_pr)
{
	int thread_index;
	
	if(0 == sapp_global_val->config.packet_io.polling_enabled){
		return;
	}

	if(NULL == pstream_pr->polling_inject_context){
		return;
	}

	thread_index = pstream_pr->stream_public.threadnum;
	if(pstream_pr->polling_inject_context->raw_pkt_up){
		sapp_raw_pkt_free(mem_used_type, thread_index, (raw_pkt_t *)pstream_pr->polling_inject_context->raw_pkt_up);
	}
	if(pstream_pr->polling_inject_context->raw_pkt_down){
		sapp_raw_pkt_free(mem_used_type, thread_index, (raw_pkt_t *)pstream_pr->polling_inject_context->raw_pkt_down);
	}	

	if(pstream_pr->polling_inject_context->meta[0]!=NULL)
	{
		dl_io_fun_list.dl_io_free_rawpkt_meta(pstream_pr->polling_inject_context->meta[0], thread_index);
		pstream_pr->polling_inject_context->meta[0]=NULL;
	}
	if(pstream_pr->polling_inject_context->meta[1]!=NULL)
	{
		dl_io_fun_list.dl_io_free_rawpkt_meta(pstream_pr->polling_inject_context->meta[1], thread_index);
		pstream_pr->polling_inject_context->meta[1]=NULL;
	}

	sapp_mem_free((sapp_mem_type_t)mem_used_type, thread_index, pstream_pr->polling_inject_context);
	pstream_pr->polling_inject_context = NULL;
}


/* 
    全局流id, stream_index历史上已经表示单机内唯一id, 此处要保证集群所有机器不重复, 
	高位 --- 低位
	1 |  12bit device_id | 8bit thread_id | 28bit timestamp in sec | 15bit sequence per thread
*/
unsigned long long get_global_stream_id(unsigned long long thread_seq)
{
#define RELATIVE_TIME_MAX (268435456L)
#define THREAD_SEQ_MAX    (32768)
	unsigned long long glo_sid = 0;
	unsigned long long stream_seq; 
	unsigned long long relative_base_time;

	stream_seq = sapp_global_val->mthread_volatile[thread_seq]->stream_seq_per_thread++ % THREAD_SEQ_MAX;
	relative_base_time = (sapp_global_val->individual_volatile->current_time - sapp_global_val->config.stream.stream_id_base_time_t) % RELATIVE_TIME_MAX;
	
	glo_sid = (thread_seq << 43) | (relative_base_time << 15) | (stream_seq);

	return glo_sid;
}

struct streaminfo_private *copy_stream_info_to_heap_single_layer(int mem_used_type, const struct streaminfo_private *stack_stream_pr, int reverse)
{
	struct streaminfo_private *heap_stream_pr = NULL;
	void *heap_addr;
	struct streaminfo *heap_stream;
	const struct streaminfo *stack_stream;

	if(NULL == stack_stream_pr){
		return NULL;
	}

	stack_stream = &(stack_stream_pr->stream_public);

	heap_stream_pr = (struct streaminfo_private *)sapp_mem_malloc((sapp_mem_type_t)mem_used_type, stack_stream->threadnum, sizeof(struct streaminfo_private));
	memcpy(heap_stream_pr, stack_stream_pr, sizeof(struct streaminfo_private));
	heap_stream = &(heap_stream_pr->stream_public);

	/* 单层streaminfo, pfather应该在外部调用者处理, 此处先设为NULL   */
	heap_stream_pr->pfather_pr = NULL;
	heap_stream_pr->stream_public.pfather = NULL;
			
	heap_addr = sapp_mem_malloc(SAPP_MEM_DYN_PADDR, stack_stream->threadnum, stack_stream->addr.addrlen);
	memset(heap_addr, 0, stack_stream->addr.addrlen);

	/* 上层地址翻转, 且不是overlay层,才能反向copy地址    	   */	
	if(reverse){
		heap_stream_pr->dirreverse=1;
		heap_stream_pr->stream_dir = 1 ^ heap_stream_pr->layer_dir; /* lijia comment, 与"src>=dst"默认规则不一致 */
		heap_stream_pr->stream_c2s_route_dir = 1 ^ heap_stream_pr->stream_c2s_route_dir; 
		//reverse_addr_new(heap_addr, heap_stream->addr.addrtype);
		/* 地址COPY时, 如果需要反转, 直接反向COPY, 不要先memcpy, 再交换地址源、目的的顺序 */
		addr_reverse_memcpy(stack_stream_pr, heap_addr, stack_stream->addr.paddr, stack_stream->addr.addrtype, stack_stream->addr.addrlen);
	}else{
		heap_stream_pr->stream_dir = heap_stream_pr->layer_dir;
		memcpy(heap_addr, stack_stream->addr.paddr, stack_stream->addr.addrlen);
	}
	
	heap_stream->addr.paddr = heap_addr;
	heap_stream->addr.addrlen = stack_stream->addr.addrlen;
	heap_stream->addr.addrtype = stack_stream->addr.addrtype;
	
	return (struct streaminfo_private *)heap_stream;
}


/* 
   2014-04-08 LiJia add,
   每个包的地址信息临时存于栈空间, 函数返回后此块内存地址就无效了, 
   创建新流时, 需copy到malloc的堆空间内, 用于以后的地址比对. 

   2014-04-08 LiJia add new arg stream_c2s_route_dir,
   因为之前的reverse的定义其实有局限性, 表示当前层地址跟'大地址是客户端'规则是否一致, 是否需要翻转,
   但是mpls, gtp等协议地址是单向的, reverse的规则不好使.
 */
struct streaminfo_private *copy_stream_info_to_heap(int mem_used_type,const struct streaminfo_private *stack_stream_pr, int reverse)
{
	struct streaminfo_private *heap_stream_pr;
	struct streaminfo *heap_stream;
	struct streaminfo_private *pfather_pr;

	if(NULL == stack_stream_pr){
		return NULL;
	}

	heap_stream_pr = copy_stream_info_to_heap_single_layer(mem_used_type, stack_stream_pr, reverse);
	heap_stream = &heap_stream_pr->stream_public;

	heap_stream_pr->pfather_pr = copy_stream_info_to_heap(mem_used_type, stack_stream_pr->pfather_pr, reverse);
	pfather_pr = stack_stream_pr->pfather_pr;
	if((pfather_pr != NULL)
	  && (DEPOLYMENT_MODE_INLINE == sapp_global_val->config.packet_io.depolyment_mode_bin)
	  && (g_overlay_layer_set[pfather_pr->stream_public.addr.addrtype][pfather_pr->layer_index] != 0)){ /* 2021-01-11 lijia add, overlay层的pfather设为NULL, 插件不可见 */
		heap_stream->pfather = NULL;
	}else{
		heap_stream->pfather = (struct streaminfo *)heap_stream_pr->pfather_pr;
	}
	
	return heap_stream_pr;
}

int sapp_is_overlay_layer(const struct streaminfo_private *stream_pr, const raw_pkt_t *rawpkt)
{
	if(DEPOLYMENT_MODE_INLINE != sapp_global_val->config.packet_io.depolyment_mode_bin && CAP_MODEL_PCAP_DUMPFILE != sapp_global_val->config.packet_io.internal.interface.type_bin){
		return 0;
	}

	if((rawpkt->vlan_flipping_couple[0] && rawpkt->vlan_flipping_couple[1]) != 0){
		/* vlan flipping是ADC自检及A串联设备特有的一种模式,  不属于overlay层 */
		return 0;
	} 
	
	if((g_overlay_layer_set[stream_pr->stream_public.addr.addrtype][stream_pr->layer_index] != 0)
	 && (OVERLAY_MODE_VXLAN == sapp_global_val->config.packet_io.packet_io_tunnel.overlay_mode_bin)){
		return 1;	
	}

	/* TODO, 目前暂时只有vxlan一种overlay模式,其他不符合的都不算overlay */

	return 0;
}


/* 
   底层驱动无数据包时, 调用这些淘汰函数, 两个目的:
   1) 实现无包超时淘汰功能, 更精确;
   2) 无数据包时提前将之前的旧流结束, 而不是靠新数据包到达时再淘汰旧流, 可以提升一些处理性能和降低包处理延时.
*/
int polling_stream_timeout(int tid)
{
	struct stream_list *plist=NULL;
	int i, ret, has_work = 0;

	for(i = UDP_ONE_STATE; i < MAX_UDP_STATE; i++){
		plist=&(G_MESA_GLOBAL_STREAM[tid]->udpList[i]);
		if( plist->cnt > 0){ 
			ret = del_stream_by_time(plist, NULL, tid);
			if(ret > 0){
				has_work = POLLING_STATE_WORK;
			}
		}
	}

	for(i = TCP_SYN_STATE; i < MAX_TCP_STATE; i++){
		plist=&(G_MESA_GLOBAL_STREAM[tid]->tcpList[i]);
		if(plist->cnt > 0){ /* polling阶段可能还没有流, 或者没有此状态的流, plist可能为NULL */
			ret = del_stream_by_time(plist, NULL, tid);
			if(ret > 0){
				has_work = POLLING_STATE_WORK;
			}
		}
	}

	return has_work;
}


static inline void sapp_get_dup_pkt_key_tcp_v4(const struct mesa_ip4_hdr *ip4hdr, const struct mesa_tcp_hdr *thdr, sapp_dup_pkt_key_v4_t *key)
{
	key->ip_addr.sip = ip4hdr->ip_src.s_addr;
	key->ip_addr.dip = ip4hdr->ip_dst.s_addr;
	key->tcp_seq = thdr->th_seq;
	key->tcp_ack = thdr->th_ack;
	key->sport = thdr->th_sport;
	key->dport = thdr->th_dport;
	key->ip_id = ip4hdr->ip_id;
	key->checksum = thdr->th_sum;
	
	return;
}

static inline void sapp_get_dup_pkt_key_udp_v4(const struct mesa_ip4_hdr *ip4hdr, const struct mesa_udp_hdr *uhdr, sapp_dup_pkt_key_v4_t *key)
{
	key->ip_addr.sip = ip4hdr->ip_src.s_addr;
	key->ip_addr.dip = ip4hdr->ip_dst.s_addr;
	key->tcp_seq = 0x5A5A5A5A; /* udp没有, 但设成0可能对某些hash函数不友好, 此处设个固定值 */
	key->tcp_ack = 0xA5A5A5A5; /* udp没有, 但设成0可能对某些hash函数不友好, 此处设个固定值 */
	key->sport = uhdr->uh_sport;
	key->dport = uhdr->uh_dport;
	key->ip_id = ip4hdr->ip_id;
	key->checksum = uhdr->uh_sum;
	
	return;
}

static inline void sapp_get_dup_pkt_key_tcp_v6(const struct mesa_ip6_hdr *ip6hdr, const struct mesa_tcp_hdr *thdr, sapp_dup_pkt_key_v6_t *key)
{
	memcpy(&key->ip_addr.sip, &ip6hdr->ip6_src, sizeof(struct in6_addr));
	memcpy(&key->ip_addr.dip, &ip6hdr->ip6_dst, sizeof(struct in6_addr));
	key->tcp_seq = thdr->th_seq;
	key->tcp_ack = thdr->th_ack;
	key->sport = thdr->th_sport;
	key->dport = thdr->th_dport;
	key->checksum = thdr->th_sum;
	
	return;
}


static inline void sapp_get_dup_pkt_key_udp_v6(const struct mesa_ip6_hdr *ip6hdr, const struct mesa_udp_hdr *uhdr, sapp_dup_pkt_key_v6_t *key)
{
	memcpy(&key->ip_addr.sip, &ip6hdr->ip6_src, sizeof(struct in6_addr));
	memcpy(&key->ip_addr.dip, &ip6hdr->ip6_dst, sizeof(struct in6_addr));
	key->tcp_seq = 0x5A5A5A5A; /* udp没有, 但设成0可能对某些hash函数不友好, 此处设个固定值 */
	key->tcp_ack = 0xA5A5A5A5; /* udp没有, 但设成0可能对某些hash函数不友好, 此处设个固定值 */
	key->sport = uhdr->uh_sport;
	key->dport = uhdr->uh_dport;
	key->checksum = uhdr->uh_sum;
	
	return;
}

extern int sapp_dup_pkt_identify_v4(int tid, const sapp_dup_pkt_key_v4_t *key);
extern int sapp_dup_pkt_mark_v4(int tid, const sapp_dup_pkt_key_v4_t *key);

int sapp_dup_pkt_identify_udp_v4(int tid, struct streaminfo_private *pstream_pr, 
		const struct mesa_ip4_hdr *ipv4_hdr, const struct mesa_udp_hdr *udp_h, int need_add_bloom_filter)
{
	int is_dup_pkt = 0;
	sapp_dup_pkt_key_v4_t dup_bloom_key;
	
	sapp_get_dup_pkt_key_udp_v4(ipv4_hdr, udp_h, &dup_bloom_key);			
	is_dup_pkt = sapp_dup_pkt_identify_v4(tid, &dup_bloom_key);
	if(is_dup_pkt != 0){
		pstream_pr->has_duplicate_pkt = 1;
	}else{
		if(need_add_bloom_filter){
			sapp_dup_pkt_mark_v4(tid, &dup_bloom_key);
		}
	}

	return is_dup_pkt;
}

extern int sapp_dup_pkt_identify_v6(int tid, const sapp_dup_pkt_key_v6_t *key);

int sapp_dup_pkt_identify_udp_v6(int tid, struct streaminfo_private *pstream_pr, 
		const struct mesa_ip6_hdr *ipv6_hdr, const struct mesa_udp_hdr *udp_h)
{
	int is_dup_pkt = 0;
	sapp_dup_pkt_key_v6_t dup_bloom_key;

	sapp_get_dup_pkt_key_udp_v6(ipv6_hdr, udp_h, &dup_bloom_key); 		
	is_dup_pkt = sapp_dup_pkt_identify_v6(tid, &dup_bloom_key);
	if(is_dup_pkt != 0){
		pstream_pr->has_duplicate_pkt = 1;
	}
	
	return is_dup_pkt;
}

extern int sapp_dup_pkt_mark_v6(int tid, const sapp_dup_pkt_key_v6_t *key);

void sapp_dup_pkt_mark_tcp(int tid, unsigned char addrtype, const void *ip_hdr, const struct mesa_tcp_hdr *tcp_h)
{
	sapp_dup_pkt_key_v4_t dup_bloom_key_v4;
	sapp_dup_pkt_key_v6_t dup_bloom_key_v6;

	if(ADDR_TYPE_IPV4 == addrtype){
		sapp_get_dup_pkt_key_tcp_v4((struct mesa_ip4_hdr *)ip_hdr, tcp_h, &dup_bloom_key_v4);		
		sapp_dup_pkt_mark_v4(tid, &dup_bloom_key_v4);
	}else{
		sapp_get_dup_pkt_key_tcp_v6((struct mesa_ip6_hdr *)ip_hdr, tcp_h, &dup_bloom_key_v6);		
		sapp_dup_pkt_mark_v6(tid, &dup_bloom_key_v6);		
	}

	return;
}

void sapp_dup_pkt_mark_udp(int tid, unsigned char addrtype, const void *ip_hdr, const struct mesa_udp_hdr *udp_h)
{
	sapp_dup_pkt_key_v4_t dup_bloom_key_v4;
	sapp_dup_pkt_key_v6_t dup_bloom_key_v6;

	if(ADDR_TYPE_IPV4 == addrtype){
		sapp_get_dup_pkt_key_udp_v4((struct mesa_ip4_hdr *)ip_hdr, udp_h, &dup_bloom_key_v4);		
		sapp_dup_pkt_mark_v4(tid, &dup_bloom_key_v4);
	}else{
		sapp_get_dup_pkt_key_udp_v6((struct mesa_ip6_hdr *)ip_hdr, udp_h, &dup_bloom_key_v6);		
		sapp_dup_pkt_mark_v6(tid, &dup_bloom_key_v6);		
	}

	return;
}


int sapp_dup_pkt_identify_tcp(int tid, struct streaminfo_private *pstream_pr,  
                              const void *ip_hdr, const struct mesa_tcp_hdr *tcp_h, int need_add_bloom_filter)
{
	int is_dup_pkt = 0;
	sapp_dup_pkt_key_v4_t dup_bloom_key_v4;
	sapp_dup_pkt_key_v6_t dup_bloom_key_v6;

	if(ADDR_TYPE_IPV4 == pstream_pr->stream_public.addr.addrtype){
		sapp_get_dup_pkt_key_tcp_v4((struct mesa_ip4_hdr *)ip_hdr, tcp_h, &dup_bloom_key_v4);		
		is_dup_pkt = sapp_dup_pkt_identify_v4(tid, &dup_bloom_key_v4);
		if(is_dup_pkt != 0){
			pstream_pr->has_duplicate_pkt = 1;
		}else{
			if(need_add_bloom_filter){
				sapp_dup_pkt_mark_v4(tid, &dup_bloom_key_v4); /* 如果不是重复包,加入bloom filter */
			}
		}
	}else{
		sapp_get_dup_pkt_key_tcp_v6((struct mesa_ip6_hdr *)ip_hdr, tcp_h, &dup_bloom_key_v6);		
		is_dup_pkt = sapp_dup_pkt_identify_v6(tid, &dup_bloom_key_v6);
		if(is_dup_pkt != 0){
			pstream_pr->has_duplicate_pkt = 1;
		}else{
			if(need_add_bloom_filter){
				sapp_dup_pkt_mark_v6(tid, &dup_bloom_key_v6); /* 如果不是重复包,加入bloom filter */
			}
		}		
	}

	return is_dup_pkt;
}

/*
	用于插件通过四元组找到当前线程的streaminfo结构, 此接口仅适用于不含隧道嵌套层的纯IPv4, IPv6地址!
*/
int find_streaminfo_by_addrv4(int thread_index, const struct stream_tuple4_v4 *tuplev4, enum stream_type_t streamtype, struct streaminfo *streaminfo_array[], int array_max_num)
{
	const struct global_stream *this_thread_stream = G_MESA_GLOBAL_STREAM[thread_index];
	struct streamindex **phashstream=NULL;
	struct streamindex *stream_hash_head = NULL;
	unsigned int hash_index, hash_max;
	int ret, match_layer_dir; /* 输入的四元组与大端口做为源的规则一致 */
	int tot_found_stream_num = 0;

	if((NULL == streaminfo_array) || (array_max_num <= 0)){
		return -1;
	}
	
	if (STREAM_TYPE_TCP == streamtype)
	{
		phashstream=this_thread_stream->tcp_stream_table;
		hash_max=tcp_stream_table_size;
	}	
	else if(STREAM_TYPE_UDP == streamtype)
	{
		phashstream=this_thread_stream->udp_stream_table;
		hash_max=udp_stream_table_size;
	}else{
		sapp_runtime_log(RLOG_LV_INFO, "find_streaminfo_by_addrv4() error, not support stream type:%d", (int)streamtype);
		return -1;
	}


	
#if USE_LINUX_KERNEL_HASH_ALGO	
	unsigned int a,b;
	unsigned short c,d;
	/* 此处参考函数: set_transport_addr() 	  ,大端口作为客户端 */
	if(ntohs(tuplev4->source) > ntohs(tuplev4->dest)){
		a = tuplev4->saddr;
		b = tuplev4->daddr;
		c = tuplev4->source;
		d =  tuplev4->dest;
		match_layer_dir = 1;
	}else{
		if(unlikely(tuplev4->source == tuplev4->dest)){
			if(ntohl(tuplev4->saddr) > ntohl(tuplev4->daddr)){
				a = tuplev4->saddr;
				b = tuplev4->daddr;
				c = tuplev4->source;
				d = tuplev4->dest;
				match_layer_dir = 1;
			}else{
				a = tuplev4->daddr;
				b = tuplev4->saddr;
				c = tuplev4->dest;
				d = tuplev4->source;
				match_layer_dir = 0;
			}
		}else{
			a = tuplev4->daddr;
			b = tuplev4->saddr;
			c = tuplev4->dest;
			d = tuplev4->source;
			match_layer_dir = 0;
		}
	}
	hash_index = sapp_jhash_4words(a,b,c,d, NULL) % hash_max;
#else
extern unsigned int tuple4_v4_make_crc_hash(const struct stream_tuple4_v4 *tuple4_v4);
	hash_index = tuple4_v4_make_crc_hash(tuplev4) % hash_max;
	if(ntohs(tuplev4->source) > ntohs(tuplev4->dest)){
		match_layer_dir = 1;
	}else{
		if(unlikely(tuplev4->source == tuplev4->dest)){
			if(ntohl(tuplev4->saddr) > ntohl(tuplev4->daddr)){
				match_layer_dir = 1;
			}else{
				match_layer_dir = 0;
			}
		}else{
			match_layer_dir = 0;
		}
	}
#endif
	stream_hash_head = phashstream[hash_index];

	while(stream_hash_head != NULL){
		if(1 == match_layer_dir){
			ret = cmpaddr_positive(stream_hash_head->stream.stream_public.addr.tuple4_v4, (void *)tuplev4, ADDR_TYPE_IPV4, sizeof(struct stream_tuple4_v4));
		}else{
			ret = cmpaddr_reverse(stream_hash_head->stream.stream_public.addr.tuple4_v4, (void *)tuplev4, ADDR_TYPE_IPV4, sizeof(struct stream_tuple4_v4));
		}

		if(0 == ret){
			streaminfo_array[tot_found_stream_num] = &stream_hash_head->stream.stream_public;
			tot_found_stream_num++;
			if(tot_found_stream_num >= array_max_num){
				break;
			}
		}
		stream_hash_head = stream_hash_head->phashnext;
	}

	return tot_found_stream_num;
}


int find_streaminfo_by_addrv6(int thread_index, const struct stream_tuple4_v6 *tuple4_v6, enum stream_type_t streamtype, struct streaminfo *streaminfo_array[], int array_max_num)
{
	const struct global_stream *this_thread_stream = G_MESA_GLOBAL_STREAM[thread_index];
	struct streamindex **phashstream=NULL;
	unsigned int hash_index, hash_max, no_use_slave_hash;
	struct streamindex *stream_hash_head = NULL;
	int ret, match_layer_dir; /* 输入的四元组与大端口做为源的规则一致 */
	int tot_found_stream_num = 0;
	
	if (STREAM_TYPE_TCP == streamtype)
	{
		phashstream=this_thread_stream->tcp_stream_table;
		hash_max=tcp_stream_table_size;
	}	
	else if(STREAM_TYPE_UDP == streamtype)
	{
		phashstream=this_thread_stream->udp_stream_table;
		hash_max=udp_stream_table_size;
	}else{
		sapp_runtime_log(RLOG_LV_INFO, "find_streaminfo_by_addrv6() error, not support streamtype:%u", (int)streamtype);
		return -1;
	}

#if USE_LINUX_KERNEL_HASH_ALGO
	unsigned int a,b,c,d;
	/* 此处参考函数: set_transport_addr() 	  ,大端口作为客户端 */
	if(ntohs(tuple4_v6->source) > ntohs(tuple4_v6->dest)){
		memcpy(&a, &tuple4_v6->saddr[12], sizeof(int));
		memcpy(&b, &tuple4_v6->daddr[12], sizeof(int));
		c = tuple4_v6->source;
		d = tuple4_v6->dest;
		match_layer_dir = 1;
	}else{
		if(unlikely(tuple4_v6->source == tuple4_v6->dest)){
			if(memcmp(tuple4_v6->saddr, tuple4_v6->daddr, IPV6_ADDR_LEN) >= 0){
				memcpy(&a, &tuple4_v6->saddr[12], sizeof(int));
				memcpy(&b, &tuple4_v6->daddr[12], sizeof(int));
				c = tuple4_v6->source;
				d = tuple4_v6->dest;
				match_layer_dir = 1;
			}else{
				memcpy(&a, &tuple4_v6->daddr[12], sizeof(int));
				memcpy(&b, &tuple4_v6->saddr[12], sizeof(int));
				c = tuple4_v6->dest;
				d = tuple4_v6->source;
				match_layer_dir = 0;
			}
		}else{
			memcpy(&a, &tuple4_v6->daddr[12], sizeof(int));
			memcpy(&b, &tuple4_v6->saddr[12], sizeof(int));
			c = tuple4_v6->dest;
			d = tuple4_v6->source;
			match_layer_dir = 0;
		}
	}
	
	hash_index = sapp_jhash_4words(a,b,c,d, &no_use_slave_hash) % hash_max;
#else
extern unsigned int tuple4_v6_make_crc_hash(const struct stream_tuple4_v6 *tuple4_v6);
	hash_index = tuple4_v6_make_crc_hash(tuple4_v6) % hash_max;
	if(ntohs(tuple4_v6->source) > ntohs(tuple4_v6->dest)){
		match_layer_dir = 1;
	}else{
		if(unlikely(tuple4_v6->source == tuple4_v6->dest)){
			if(memcmp(tuple4_v6->saddr, tuple4_v6->daddr, IPV6_ADDR_LEN) >= 0){
				match_layer_dir = 1;
			}else{
				match_layer_dir = 0;
			}
		}else{
			match_layer_dir = 0;
		}
	}	
#endif
	stream_hash_head = phashstream[hash_index];


	while(stream_hash_head != NULL){
		if(1 == match_layer_dir){
			ret = cmpaddr_positive(stream_hash_head->stream.stream_public.addr.tuple4_v6, (void *)tuple4_v6, ADDR_TYPE_IPV6, sizeof(struct stream_tuple4_v6));
		}else{
			ret = cmpaddr_reverse(stream_hash_head->stream.stream_public.addr.tuple4_v6, (void *)tuple4_v6, ADDR_TYPE_IPV6, sizeof(struct stream_tuple4_v6));
		}

		if(0 == ret){
			streaminfo_array[tot_found_stream_num] = &stream_hash_head->stream.stream_public;
			tot_found_stream_num++;
			if(tot_found_stream_num >= array_max_num){
				break;
			}			
		}
		stream_hash_head = stream_hash_head->phashnext;
	}

	return tot_found_stream_num;
}

extern int stream_bridge_init(void);

int init_stream_manage(int threadcount)
{
	int i;
	
	//wy_init_hash();
	
	for(i=0;i<MAX_TCP_STATE;i++)
		tcp_stream_table_size+=tcpstate_num[i];
	for(i=0;i<MAX_UDP_STATE;i++)
		udp_stream_table_size+=udpstate_num[i];

	G_MESA_GLOBAL_STREAM = (struct global_stream **)sapp_mem_malloc(SAPP_MEM_FIX_GLOBAL_STREAM, -1, threadcount * sizeof (char *));
 	memset (G_MESA_GLOBAL_STREAM, 0, threadcount * sizeof (char *));
	for(i=0;i<threadcount;i++)
	{
		G_MESA_GLOBAL_STREAM[i]=(struct global_stream *)sapp_mem_malloc(SAPP_MEM_FIX_GLOBAL_STREAM, -1, sizeof(struct global_stream));
		init_stream_detail(G_MESA_GLOBAL_STREAM[i]);
	}

	//add 20140626 	初始化procject接口
	project_requirement_global_init();

	if(stream_bridge_init() < 0){
		exit(1);
	}

	return 0;   
}


void global_stream_destroy(void)
{
	int tseq;

	for(tseq = 0; tseq < g_packet_io_thread_num; tseq++){
		sapp_mem_free(SAPP_MEM_FIX_GLOBAL_STREAM, -1, G_MESA_GLOBAL_STREAM[tseq]->tcp_stream_table);
		sapp_mem_free(SAPP_MEM_FIX_GLOBAL_STREAM, -1, G_MESA_GLOBAL_STREAM[tseq]->udp_stream_table);
		sapp_mem_free(SAPP_MEM_FIX_GLOBAL_STREAM, -1, G_MESA_GLOBAL_STREAM[tseq]->tcp_stream_talbe_hash_count);
		sapp_mem_free(SAPP_MEM_FIX_GLOBAL_STREAM, -1, G_MESA_GLOBAL_STREAM[tseq]->udp_stream_talbe_hash_count);
		sapp_mem_free(SAPP_MEM_FIX_GLOBAL_STREAM, -1, G_MESA_GLOBAL_STREAM[tseq]->__freeList_real_head);

		sapp_mem_free(SAPP_MEM_FIX_GLOBAL_STREAM, -1, G_MESA_GLOBAL_STREAM[tseq]);
	}
	sapp_mem_free(SAPP_MEM_FIX_GLOBAL_STREAM, -1, G_MESA_GLOBAL_STREAM);
	G_MESA_GLOBAL_STREAM = NULL;
	
	tcp_stream_table_size = 0;
	udp_stream_table_size = 0;
}
		

#ifdef __cplusplus
}
#endif
