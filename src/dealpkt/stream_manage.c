
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

#ifdef __cplusplus
extern "C" {
#endif

int sapp_version_v4_20191119;

/* 
	下面的版本号用于packet_io_lib校验, 防止平台和dl.so不匹配导致运行异常, 或已修复的BUG未更新.
*/
#if IOMODE_PCAP
int sapp_packet_io_v = 20190820;
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

//int g_sapp_log_level = 20;
///void *g_sapp_log_handle;

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
	int i=0;
	memset(g_stream,0,sizeof(struct global_stream));
	for(i=0;i<MAX_TCP_STATE;i++)
	{
		g_stream->tcpList[i].max_cnt=tcpstate_num[i];

		//add by lqy限制每次换出最大数目为100
		g_stream->tcpList[i].sift_out_cnt=g_stream->tcpList[i].max_cnt/50+1;
#if 0		
		if(g_stream->tcpList[i].sift_out_cnt>100)
			g_stream->tcpList[i].sift_out_cnt=100;		
#else
		g_stream->tcpList[i].sift_out_cnt=1; /* lijia modify, 减少单包延时太长, 每次只淘汰一个 */		
#endif
		g_stream->tcpList[i].cnt=0;
	}	
	for(i=0;i<MAX_UDP_STATE;i++)
	{
		g_stream->udpList[i].max_cnt=udpstate_num[i];
		//add by lqy限制每次换出最大数目为100
		g_stream->udpList[i].sift_out_cnt=g_stream->udpList[i].max_cnt/50+1;
#if 0			
		if(g_stream->udpList[i].sift_out_cnt>100)
			g_stream->udpList[i].sift_out_cnt=100;		
#else
		g_stream->udpList[i].sift_out_cnt=1; /* lijia modify, 减少单包延时太长, 每次只淘汰一个 */			
#endif
		g_stream->udpList[i].cnt=0;
	}	
 	g_stream->freeList.max_cnt=tcp_stream_table_size+udp_stream_table_size;
	g_stream->freeList.cnt=0;

	//预先分配hash指针
#if USE_RBTREE_INSTEAD_LIST
	g_stream->tcp_rb_root_table = (struct rb_root *)malloc (tcp_stream_table_size * sizeof (struct rb_root));
	memset(g_stream->tcp_rb_root_table, 0, tcp_stream_table_size * sizeof (struct rb_root));

	g_stream->udp_rb_root_table = (struct rb_root *)malloc (tcp_stream_table_size * sizeof (struct rb_root));
	memset(g_stream->udp_rb_root_table, 0, tcp_stream_table_size * sizeof (struct rb_root));
#else
	g_stream->tcp_stream_table = (struct streamindex **)malloc (tcp_stream_table_size * sizeof (char *));
    memset (g_stream->tcp_stream_table, 0, tcp_stream_table_size* sizeof (char *));
    g_stream->udp_stream_table = (struct streamindex **)malloc (udp_stream_table_size * sizeof (char *));
    memset (g_stream->udp_stream_table, 0, udp_stream_table_size* sizeof (char *));
   //记录hash的状态
    g_stream->tcp_stream_talbe_hash_count = (unsigned short *)malloc (tcp_stream_table_size*  sizeof (short));
    memset (g_stream->tcp_stream_talbe_hash_count, 0, tcp_stream_table_size* sizeof (short));
    g_stream->udp_stream_talbe_hash_count = (unsigned short *)malloc (udp_stream_table_size*  sizeof (short));
    memset (g_stream->udp_stream_talbe_hash_count, 0, udp_stream_table_size* sizeof (short));
#endif
	
    g_stream->freeList.head=(struct  streamindex *) malloc ((g_stream->freeList.max_cnt) * sizeof (struct streamindex));
    memset(g_stream->freeList.head, 0,(g_stream->freeList.max_cnt) * sizeof (struct streamindex));
    for (i = 0; i < g_stream->freeList.max_cnt-1; i++)
    {
    	g_stream->freeList.head[i].next= &(g_stream->freeList.head[i + 1]);
		g_stream->freeList.head[i+1].prev=&(g_stream->freeList.head[i]);
		//g_stream->freeList.index=i; // 为每个链接增加一个全局索引号
		 //adjust by lqy 20150113
		g_stream->freeList.head[i].stream.stream_public.stream_index=i;	
    }
    g_stream->freeList.head[g_stream->freeList.max_cnt-1].next=NULL;
	 //adjust by lqy 20150113
	g_stream->freeList.head[g_stream->freeList.max_cnt-1].stream.stream_public.stream_index=i;	    
    g_stream->freeList.cnt=g_stream->freeList.max_cnt;
    g_stream->freeList.tail= &(g_stream->freeList.head[g_stream->freeList.max_cnt-1]);	

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
	struct streamindex *tmp_index;
	struct stream_list *lru_list_root;
	const struct streaminfo *pstream = &pindex->stream.stream_public;
	
//long search_times = 0;

	if(STREAM_TYPE_TCP == pindex->stream.stream_public.type){
		global_default_timeout = link_default_nopkt_time;
		lru_list_root=&(G_MESA_GLOBAL_STREAM[pstream->threadnum]->tcpList[pstream->stream_state]);
	}else{
		global_default_timeout = udp_reset_time;
		lru_list_root=&(G_MESA_GLOBAL_STREAM[pstream->threadnum]->udpList[pstream->stream_state]);
	}

	if(lru_list_root->head == lru_list_root->tail){ /* 当前仅剩最后一个流, 无需移动 */
		return;
	}

	assert(lru_list_root->head);
	assert(lru_list_root->tail);	
	__do_streamleavlist(pindex, lru_list_root); /* 从原位置摘除 */
	assert(lru_list_root->head);
	assert(lru_list_root->tail);
		
	if(global_default_timeout > 0){
		/* 
		    如果设置了全局超时时间, 新增的节点应该从tail->head方向遍历,
             因为新增的节点超时时间长, 而且是当前流在设置, 肯定比所有默认的流, 以及大多数曾设置过超时的流更晚超时.   
		*/
		/* 
		   如果当前流设置的新超时时间, 比LRU末尾的流剩余时间(无包到达时间)还长, 
		   换句话说, 就是离淘汰此流的时间也比LRU末尾的流要滞后, 
		   所以需要向tail(时间更新的)方向移动 .
		 */
		/* after-insert : head->pindex->tmp_index->tail, 插在tmp_index之前 */
		tmp_index = lru_list_root->tail; /* 新设的timeout值大, 从不易被淘汰端, 即tail节点开始比较 */
		while(tmp_index 
		  && (new_timeout < (tmp_index->stream.timeout -(g_CurrentTime -stream_get_detail_last_mtime(tmp_index))))){ /* 新的超时时间 < tmp流的剩余生存时间 */
//printf("##### serach udp timeout place, %ld.....\n", search_times++);			  
			tmp_index = tmp_index->prev;
		}			

		/* 插入新位置 */
		if(NULL == tmp_index){ /* 从tail开始一直找到最后一个节点, pindex应该做为新的head */
			lru_list_root->head->prev = pindex;
			pindex->next = lru_list_root->head;
			lru_list_root->head = pindex;
			pindex->prev = NULL;
		}else{			
			if(tmp_index->prev){
				tmp_index->prev->next = pindex;
			}else{
				lru_list_root->head = pindex; /* 作为head节点 */
			}
			pindex->prev = tmp_index->prev;
			tmp_index->prev = pindex;
			pindex->next = tmp_index;
		}
	}else{
		/* 
		    如果没有设置了全局超时时间, 可认为默认超时时间时无限长, 仅靠流表满之后才强制淘汰已有流.
		    那么新增的节点应该从head->tail方向遍历,
             因为新增的节点超时时间最长也就65535秒, 肯定比现有的流更早超时.   
		*/
		tmp_index = lru_list_root->head; /* 新设的timeout比默认0更容易被淘汰 */
		while(tmp_index 
		  && (tmp_index->stream.timeout != 0) /* 之前某个流也单独设置了超时时间 */
		  && (new_timeout > (tmp_index->stream.timeout - (g_CurrentTime -stream_get_detail_last_mtime(tmp_index))))){ /* 新的超时时间 > tmp流的剩余生存时间 */
//printf("##### serach udp timeout place, %ld.....\n", search_times++);			  
			tmp_index = tmp_index->next;
		}		

		/* 插入新位置 */
		if(NULL == tmp_index){ /* 从head开始一直找到最后一个节点, pindex应该做为新的tail */
			lru_list_root->tail->next = pindex;
			pindex->prev = lru_list_root->tail;
			lru_list_root->tail = pindex;
			pindex->next = NULL;
		}else{			
			if(tmp_index->prev){
				tmp_index->prev->next = pindex;
			}else{
				lru_list_root->head = pindex; /* 作为head节点 */
			}
			pindex->prev = tmp_index->prev;
			tmp_index->prev = pindex;
			pindex->next = tmp_index;
		}		
	}

	lru_list_root->cnt++; /* 在__do_streamleavlist()中减1, 此处恢复计数 */
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
			if(sapp_global_mthread[pstream->threadnum].udp_stream_special_timeout_num >= udpstate_num[UDP_TWO_STATE]/5){
				return -2;
			}
			if(pstream_pr->timeout == udp_reset_time){ 
				/* 允许插件多次设置超时时间, 当前流第一次设置超时时间记录计数 */
				sapp_global_mthread[pstream->threadnum].udp_stream_special_timeout_num++;
			}
#if 0			
			lru_list_root=&(G_MESA_GLOBAL_STREAM[pstream->threadnum]->udpList[pstream->stream_state]);
			if(lru_list_root->head == lru_list_root->tail){ /* 当前仅剩最后一个流, 无需移动 */
				ret = 0;
				goto done;
			}

			/* before-insert : head->tmp_index->tail */

			assert(lru_list_root->head);
			assert(lru_list_root->tail);	
			__do_streamleavlist(pindex, lru_list_root); /* 从原位置摘除 */
			assert(lru_list_root->head);
			assert(lru_list_root->tail);
			/* 
			   如果当前流设置的新超时时间, 比LRU末尾的流剩余时间(无包到达时间)还长, 
			   换句话说, 就是离淘汰此流的时间也比LRU末尾的流要滞后, 
			   所以需要向tail(时间更新的)方向移动 .
			 */
			/* after-insert : head->pindex->tmp_index->tail, 插在tmp_index之前 */
long udp_times = 0;
			tmp_index = lru_list_root->tail; /* 新设的timeout值大, 从不易被淘汰端, 即tail节点开始比较 */
			while(tmp_index 
			  && (tmp_index->stream.timeout != 0) /* timeout默认为0的流, 即没设超时时间, 可认为是无限大 */
			  && (timeout < (g_CurrentTime - tmp_index->stream.stream_public.pudpdetail->lastmtime))){
printf("##### serach udp timeout place, %ld.....\n", udp_times++);			  
				tmp_index = tmp_index->prev;
			}			

			/* 插入新位置 */
			if(NULL == tmp_index){ /* 一直找到最后一个节点, pindex应该做为新的head */
				lru_list_root->head->prev = pindex;
				pindex->next = lru_list_root->head;
				lru_list_root->head = pindex;
				pindex->prev = NULL;
			}else{			
				if(tmp_index->prev){
					tmp_index->prev->next = pindex;
				}else{
					lru_list_root->head = pindex; /* 作为head节点 */
				}
				pindex->prev = tmp_index->prev;
				tmp_index->prev = pindex;
				pindex->next = tmp_index;
			}
			lru_list_root->cnt++; /* 在__do_streamleavlist()中减1, 此处恢复计数 */
#endif			
		}
		else if (STREAM_TYPE_TCP==pstream->type)
		{
			if(timeout < link_default_nopkt_time){ /* 必须比全局默认值大, 且不能比之前设置的小 */
				return -1;
			}		
			if(sapp_global_mthread[pstream->threadnum].tcp_stream_special_timeout_num >= tcpstate_num[TCP_DATA_STATE]/10){
				return -2;
			}		
			if(pstream_pr->timeout == link_default_nopkt_time){ 
				/* 允许插件多次设置超时时间, 当前流第一次设置超时时间记录计数 */
				sapp_global_mthread[pstream->threadnum].tcp_stream_special_timeout_num++;
			}
#if 0			
			lru_list_root=&(G_MESA_GLOBAL_STREAM[pstream->threadnum]->tcpList[pstream->stream_state]);
			if(lru_list_root->head == lru_list_root->tail){ /* 当前仅剩最后一个流, 无需移动 */
				ret = 0;
				goto done;
			}			
			
			assert(lru_list_root->head);
			assert(lru_list_root->tail);	
			__do_streamleavlist(pindex, lru_list_root); /* 从原位置摘除, 此处不能直接使用streamleavlist, 复用部分代码 */
			assert(lru_list_root->head);
			assert(lru_list_root->tail);	
			/* 
			   如果当前流设置的新超时时间, 比LRU末尾的流剩余时间(无包到达时间)还长, 
			   换句话说, 就是离淘汰此流的时间也比LRU末尾的流要滞后, 
			   所以需要向tail(时间更新的)方向移动 .
			   */	
long tcp_times = 0;
			tmp_index = lru_list_root->tail;
			while(tmp_index 
			  && (tmp_index->stream.timeout != 0) /* timeout默认为0的流, 即没设超时时间, 可认为是无限大 */
			  && (timeout < (g_CurrentTime - tmp_index->stream.stream_public.ptcpdetail->lastmtime))){
printf("##### serach tcp timeout place, %ld.....\n", tcp_times);			
				tmp_index = tmp_index->prev;
			}	
		
			/* 插入新位置 */
			if(NULL == tmp_index){ /* 一直找到最后一个节点, pindex应该做为新的head */
				lru_list_root->head->prev = pindex;
				pindex->next = lru_list_root->head;
				lru_list_root->head = pindex;
				pindex->prev = NULL;
			}else{			
				if(tmp_index->prev){
					tmp_index->prev->next = pindex;
				}else{
					lru_list_root->head = pindex; /* 作为head节点 */
				}
				pindex->prev = tmp_index->prev;
				tmp_index->prev = pindex;
				pindex->next = tmp_index;
			}
			lru_list_root->cnt++; /* 在__do_streamleavlist()中减1, 此处恢复计数 */
#endif	
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
#if 0
void udp_set_stream_resettime(unsigned short timeout)
{
	udp_reset_time=timeout;
}
#endif

#if 0
void udp_set_stream_timeout(unsigned short timeout)//2014-12-25 lijia add, 兼容旧平台, xj_fd
{
	udp_reset_time=(unsigned short)timeout;
}

void udp_set_stream_resettime(unsigned short timeout)
{
	udp_reset_time=(unsigned short)timeout;
}#endif
#endif

int udp_set_stream_num(int udp1,int udp2,int udp3)
{
	udpstate_num[UDP_ONE_STATE]=udp1;
	udpstate_num[UDP_TWO_STATE]=udp2;
	udpstate_num[UDP_MORE_STATE]=udp3;
	
	return 0;	
}

int init_stream_manage(int threadcount)
{
	int i;
	
	wy_init_hash();
	for(i=0;i<MAX_TCP_STATE;i++)
		tcp_stream_table_size+=tcpstate_num[i];
	for(i=0;i<MAX_UDP_STATE;i++)
		udp_stream_table_size+=udpstate_num[i];

	G_MESA_GLOBAL_STREAM = (struct global_stream **)malloc(threadcount * sizeof (char *));
 	memset (G_MESA_GLOBAL_STREAM, 0, threadcount * sizeof (char *));
	for(i=0;i<threadcount;i++)
	{
		G_MESA_GLOBAL_STREAM[i]=(struct global_stream *)malloc(sizeof(struct global_stream));
		init_stream_detail(G_MESA_GLOBAL_STREAM[i]);
	}

	//add 20140626 	初始化procject接口
	project_requirement_global_init();

	if(stream_bridge_init() < 0){
		exit(1);
	}

	return 0;   
}

static struct streaminfo *del_stream(struct streamindex *pindex)
{
	struct streaminfo_private *pstream_pr=&(pindex->stream);
	struct streaminfo *pstream=&(pstream_pr->stream_public);
	
	if(STREAM_TYPE_UDP==pstream->type)
	{
		pstream_pr->stream_close_reason = STREAM_CLOSE_REASON_LRUOUT;
		udp_free_stream(pindex);
	}
	else if (STREAM_TYPE_TCP==pstream->type)
	{
		((struct tcpdetail_private*)(pstream->pdetail))->link_state=STREAM_LINK_LRU_OUT;
		tcp_free_stream(pindex, NULL,NULL,NULL);
	}

	return NULL;
}

static inline void __do_streamleavlist(struct streamindex *pindex,struct stream_list *plist)
{
	if(pindex->prev != NULL)
	{
		pindex->prev->next = pindex->next;
	}
	else
	{
		plist->head=pindex->next;
		if(plist->head!=NULL)
			plist->head->prev = NULL;
	}
	if(pindex->next != NULL)
	{
		pindex->next->prev = pindex->prev;
	}
	else
	{
		plist->tail = pindex->prev;
		if(plist->tail!=NULL)
			plist->tail->next = NULL;
	}
	pindex->next= NULL;   /* NOTE: 此处应置空, 后续可能还有addlist操作 */
	pindex->prev = NULL; /* NOTE: 此处应置空, 后续可能还有addlist操作 */
	plist->cnt--;

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
	struct streamindex *tmpstream;
	struct streaminfo *pstream=(struct streaminfo *)(&(pindex->stream));
	if((plist->head != NULL) && (plist->cnt >= plist->max_cnt-1))
	{
		//每次淘汰总大小的2%
		//istreamdelnum=plist->max_cnt/50+1;
		//adjust by lqy 20140810
		//istreamdelnum=plist->sift_out_cnt;

		/* 
			2017-06-07 lijia add,
			先判断当前LRU末尾的流是否到了超时时间, 可能是保护IM等包数少、时间长的流 
			风险: 如果全局默认是60秒, 但因为流数太多, 都没到达超时时间, 怎么办? 

			使用组合条件, if(pstream->timtout > defalut) && (g_current - lastmtime < pstream->timtout)
			
		*/
		tmpstream = plist->head;

		while(tmpstream){
			if(STREAM_TYPE_TCP == tmpstream->stream.stream_public.type){
				/* 当前流独有超时时间比默认全局的大, 且还没有超时, 不能淘汰! */
				if((tmpstream->stream.timeout > link_default_nopkt_time)
				 && (g_CurrentTime - tmpstream->stream.stream_public.ptcpdetail->lastmtime < tmpstream->stream.timeout)){
/*				 
printf("###### %s timeout is %d, remain %lld, can't be free!\n", printaddr(&tmpstream->stream.stream_public.addr, tmpstream->stream.stream_public.threadnum),
			tmpstream->stream.timeout,
			g_CurrentTime - tmpstream->stream.stream_public.ptcpdetail->lastmtime);
*/			
					tmpstream = tmpstream->next;
				 }else{
					del_stream(tmpstream);
					break;
				 }	
			}else{
				if((tmpstream->stream.timeout > udp_reset_time)
				 && (g_CurrentTime - tmpstream->stream.stream_public.pudpdetail->lastmtime < tmpstream->stream.timeout)){
					tmpstream = tmpstream->next;
				 }else{
					del_stream(tmpstream);
					break;
				 }	
			}
		}
	}
	
	pindex->prev = plist->tail;
	pindex->next= NULL;
	if(plist->tail != NULL)
	{
		plist->tail->next = pindex;
		plist->tail = pindex;
	}
	else
	{
		plist->tail = pindex;
		plist->head = pindex;
	}
	plist->cnt++;
	//add by lqy 20120919 just for show

#if 0		
	if(pstream->type==STREAM_TYPE_TCP)
	{
		switch(pstream->stream_state)
		{
			case TCP_SYN_STATE:
					stream_info[pstream->threadnum].syn_cnt++;
					break;
			case TCP_DATA_STATE:
					stream_info[pstream->threadnum].ack_cnt++;
					break;
			case TCP_NOUSE_STATE:
					stream_info[pstream->threadnum].tcp_num++;
					break;
		}
		
	}
#endif		
	update_stream_status(pstream->threadnum, pstream->type, pstream->stream_state, 1);

	/* Fix bug, 放在streamaddlist函数, 每个流状态变化时会生成多个不同的streamid, 移动至hash_add_stream */
	//pindex->stream.global_stream_id = get_global_stream_id(pstream->threadnum);
}



//struct streamindex *malloc_streamindex(int threadnum)
struct streamindex *malloc_and_copy_streamindex(int threadnum, struct streamindex *pindex_stack)
{
	struct streamindex *pindex=NULL;
	struct global_stream *g_stream=G_MESA_GLOBAL_STREAM[threadnum];

	pindex =g_stream->freeList.head;

	g_stream->freeList.index=pindex->stream.stream_public.stream_index;//add by lqy 20150113
	g_stream->freeList.head=pindex->next;
	g_stream->freeList.cnt--;
		
	memcpy(pindex,pindex_stack,sizeof(struct streamindex));

	pindex->stream.stream_public.stream_index=g_stream->freeList.index;

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
	//free(pindex);
	if(g_stream->freeList.tail==NULL)
	{
		assert(0);
		pindex->prev=NULL;
		pindex->next=NULL;
		g_stream->freeList.tail=pindex;
		g_stream->freeList.head=pindex;
	}
	else
	{
		g_stream->freeList.tail->next=pindex;
		pindex->prev=g_stream->freeList.tail;
		pindex->next=NULL;
		g_stream->freeList.tail=pindex;
		
	}
	g_stream->freeList.cnt++;
	
}

//add by lqy 20141203
//检测链表尾部的最后一个链接是否超时，如果超时则淘汰之

/* 2015-06-10 lijia add arg "current_drive_index", 表示当前流结构指针 
	return value:
		0: normal;
		1: del self by time.

	modify by lqy 20150612
	超时删除从链表头部开始，一次删除		
*/
int del_stream_by_time(struct stream_list *plist, const struct streamindex *current_drive_index)
{
	struct streamindex *pindex;
	struct streaminfo_private *pstream_pr;
	struct streaminfo *pstream;
	long lastmtime;

	pindex=plist->head;
	pstream_pr=(&(pindex->stream));

	if(0 == pstream_pr->timeout){ /* 未开启超时淘汰 */
		return 0 ;		
	}
	
	pstream=&pstream_pr->stream_public;
	
	if(STREAM_TYPE_UDP==pstream->type)
	{
		lastmtime=((struct udpdetail *)(pstream->pdetail))->lastmtime;
	}
	else if (STREAM_TYPE_TCP==pstream->type)
	{
		lastmtime=((struct tcpdetail *)(pstream->pdetail))->lastmtime;
	}
	else
	{
		sapp_runtime_log(RLOG_LV_FATAL, "%s:%d: del_stream_by_time() error! stream->type is:%d, not TCP or UDP.\n", __FILE__, __LINE__, pstream->type);	
		return -1;
		//assert(0);
	}

	//如果设定了超时时间，并且已经超时
	if(unlikely(g_CurrentTime-lastmtime > pstream_pr->timeout))
	{
		if(pindex == current_drive_index){ /* 当前包所在的流超时, 说明之前很长时间没有包到来, 此时不用free, 而是返回1, 再调用reset */
			if (STREAM_TYPE_TCP==pstream->type)
			{
				/* 2016-12-15 lijia add, 超时reset之前, 先要设置link_state */
				((struct tcpdetail_private *)(pstream->pdetail))->link_state=STREAM_LINK_TIMEOUT;
			}			
			return 1;
		}	
#if 0	 /* 2016-12-15 lijia close, 链表相关操作在tcp_free_stream()做, 此处两次会造成指针混乱, 内存泄漏, 或其他未知BUG */	
		if(pindex->next!=NULL)
		{
			pindex->next->prev =NULL;
			plist->head= pindex->next;
		}
		else
		{
			plist->head=plist->tail=NULL;
		}
#endif		
		if (STREAM_TYPE_TCP==pstream->type)
		{
			((struct tcpdetail_private *)(pstream->pdetail))->link_state=STREAM_LINK_TIMEOUT;
			tcp_free_stream(pindex, NULL,NULL,NULL);
		}
		else
		{
			pstream_pr->stream_close_reason = STREAM_CLOSE_REASON_TIMEOUT;
			udp_free_stream(pindex);
		}		
	}

	return 0;
}

/*
	return value:
		0: normal;
		1: del self by timeout, need reset.
*/
int lrustream(struct streamindex *pindex)
{
	struct stream_list *plist=NULL;
	struct streamindex * next,*prev;
	struct streaminfo_private *pstream_pr=&(pindex->stream);
	struct streaminfo *pstream = &pstream_pr->stream_public;
	
	if(STREAM_TYPE_UDP==pstream->type)
	{
		plist=&(G_MESA_GLOBAL_STREAM[pstream->threadnum]->udpList[pstream->stream_state]);
		if(1 == del_stream_by_time(plist, pindex)){
			return 1;
		}
	}
	else if (STREAM_TYPE_TCP==pstream->type)
	{
		plist=&(G_MESA_GLOBAL_STREAM[pstream->threadnum]->tcpList[pstream->stream_state]);
		/* 2015-06-10 lijia modify, UDP使用udp_reset_stream_bytime()淘汰 */
		if(1 ==  del_stream_by_time(plist, pindex)){
			return 1;
		}
	}
	
//	if ( plist->cnt > STREAM_ONCE_DEL_NUM &&
	if(plist->tail && (plist->tail != pindex)) /* 如果当前节点不在链表最新处, LRU */
	 {
		next = pindex->next;
		prev = pindex->prev;
		if(next) next->prev = prev;
		if(prev) prev->next = next;	
		plist->tail->next = pindex ;
		pindex->prev = plist->tail;
		pindex->next = NULL;
		plist->tail= pindex;

		if(plist->head == pindex) 
		{
			plist->head = next;
			plist->head->prev = NULL;
		}
	}
	
	return 0;
}

#if (0 == USE_LINUX_KERNEL_HASH_ALGO)
static int mkstreamhash_single(struct streaminfo_private *pstream_pr, int maxsize)
{
	char addr_hash_buf[MTU_MAX];
	char *hdata;
	struct streaminfo *this_stream = &pstream_pr->stream_public;
	struct layer_addr *saddr = &this_stream->addr;

	/* lijia comment, 计算hash时使用同一种方向, 即"src>=dst" */

	/* 四元组特殊, 用作一个整体, 此时只能看ip的方向, 端口信息无法通过指针回溯回去, 固不再使用 */
	if(0 == pstream_pr->layer_dir){
		memcpy(addr_hash_buf, saddr->paddr, this_stream->addr.addrlen);
		reverse_addr((void *)addr_hash_buf, saddr->addrtype);
		hdata = (char *)&addr_hash_buf[0];
	}else{
		hdata = (char *)(saddr->paddr);
	}
	
	return mkaddrhash(hdata, this_stream->addr.addrlen) % maxsize;
}


int mkstreamhash_new(struct streaminfo_private *pstream_pr, int maxsize)
{
	int hash = 0;
	struct streaminfo *this_stream = &pstream_pr->stream_public;

	switch(this_stream->addr.addrtype){
		case __ADDR_TYPE_IP_PAIR_V4:
		case __ADDR_TYPE_IP_PAIR_V6:
		case ADDR_TYPE_VLAN:
		case ADDR_TYPE_MAC:
		case ADDR_TYPE_PPPOE_SES:
		case ADDR_TYPE_L2TP:  
			hash = mkstreamhash_single(pstream_pr, maxsize);
		break;

		case ADDR_TYPE_IPV4:
		case ADDR_TYPE_IPV6:		
		case ADDR_TYPE_TCP:
		case ADDR_TYPE_UDP:
#if 0		
			/* 
			    TCP和UDP协议较特殊, 如果只用本层的端口计算HASH, 冲突率太高, 
			    需要加上fstream中的IP地址, 使用四元组一起计算.
			*/
			hash = mkstreamhash_dual(this_stream, maxsize);
#else
			hash = mkstreamhash_new((struct streaminfo_private *)this_stream->pfather, maxsize);
#endif
		break;
		break;
		
		default:
			//printf("Unknown addr type:%d!", this_stream->addr.addrtype);
			sapp_runtime_log(RLOG_LV_FATAL, "%s:%d: mkstreamhash_new() Unknown addr type:%d.\n", __FILE__, __LINE__, this_stream->addr.addrtype);	
			//assert(0);
			return -1;
		break;
	}

	return hash;
}
#endif


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


#if USE_RBTREE_INSTEAD_LIST
/*
	pheap_stream_pr : already in stream htable.
	pstack_stream_pr: new element recv from network;
*/
static int cmpaddr_new(struct streaminfo_private *pheap_stream_pr, 
					struct streaminfo_private *pstack_stream_pr, unsigned short hash_elem_count)
{
	int ret;
	struct layer_addr *heap_addr, *stack_addr;

	heap_addr = &pheap_stream_pr->stream_public.addr;
	stack_addr = &pstack_stream_pr->stream_public.addr;

	if(pheap_stream_pr->stream_dir == pstack_stream_pr->layer_dir){
		struct stream_tuple4_v4 *ip4_addr_heap = (struct stream_tuple4_v4 *)heap_addr->tuple4_v4;
		struct stream_tuple4_v4 *ip4_addr_stack = (struct stream_tuple4_v4 *)stack_addr->tuple4_v4;

		/* 2015-07-15 lijia modify, 最可能不一样的变量放在最前面比较 */
		ret = (int)ip4_addr_heap->source - (int)ip4_addr_stack->source;
		if(ret != 0){
			goto done;
		}
		ret = (int)ip4_addr_heap->saddr - (int)ip4_addr_stack->saddr;
		if(ret != 0){
			goto done;
		}
		ret = (int)ip4_addr_heap->daddr - (int)ip4_addr_stack->daddr;
		if(ret != 0){
			goto done;
		}
		ret = (int)ip4_addr_heap->dest - (int)ip4_addr_stack->dest;
		if(ret != 0){
			goto done;
		}	

		ret = 0;
	}else{
		struct stream_tuple4_v4 *ip4_addr_heap = (struct stream_tuple4_v4 *)heap_addr->tuple4_v4;
		struct stream_tuple4_v4 *ip4_addr_stack = (struct stream_tuple4_v4 *)stack_addr->tuple4_v4;

		/* 2015-07-15 lijia modify, 最可能不一样的变量放在最前面比较 */
		ret = (int)ip4_addr_heap->source - (int)ip4_addr_stack->dest;
		if(ret != 0){
			goto done;
		}
		ret = (int)ip4_addr_heap->saddr - (int)ip4_addr_stack->daddr;
		if(ret != 0){
			goto done;
		}
		ret = (int)ip4_addr_heap->daddr - (int)ip4_addr_stack->saddr;
		if(ret != 0){
			goto done;
		}
		ret = (int)ip4_addr_heap->dest - (int)ip4_addr_stack->source;
		if(ret != 0){
			goto done;
		}

		ret = 0;
	}

done:	
	if(0 == ret){
		//pst1->p_layer_header = pst2->p_layer_header;
		pheap_stream_pr->offset_to_raw_pkt_hdr = pstack_stream_pr->offset_to_raw_pkt_hdr;
	}

	return ret;
}
#else

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

#endif



/*
	GTP的端口可能两侧都不一样, 即asymmetric addr,
	此处更新端口以最后一次ip或teid改变的包为准.
*/
static void update_outer_addr_for_gtp_tunnel(const struct streaminfo_private *top_stream_pr, 
	struct streaminfo_private *pheap_gtp_stream_pr, struct streaminfo_private *pstack_gtp_stream_pr,
	struct streaminfo_private *pheap_ip_stream_pr, struct streaminfo_private *pstack_ip_stream_pr, unsigned char cur_pkt_dir)
{
	int ret;
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
		
		if(addr_has_changed){
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
	if(pheap_stream->addr.tuple4_v4->saddr == pstack_stream->addr.tuple4_v4->saddr){
		this_layer_is_same = 1;
		cur_pkt_dir = DIR_C2S;
	}else if(pheap_stream->addr.tuple4_v4->daddr == pstack_stream->addr.tuple4_v4->daddr){
		this_layer_is_same = 1;
		cur_pkt_dir = DIR_C2S;
	}else if(pheap_stream->addr.tuple4_v4->saddr == pstack_stream->addr.tuple4_v4->daddr){
		this_layer_is_same = 1;
		cur_pkt_dir = DIR_S2C;
	}else if(pheap_stream->addr.tuple4_v4->daddr == pstack_stream->addr.tuple4_v4->saddr){
		this_layer_is_same = 1;
		cur_pkt_dir = DIR_S2C;
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
		update_outer_addr_for_gtp_tunnel(top_stream_pr, pheap_gtp_stream_pr, pstack_gtp_stream_pr, pheap_ip_stream_pr, pstack_ip_stream_pr, cur_pkt_dir);
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
		new_heap_tmp = copy_stream_info_to_heap_single_layer(stack_stream_pr->pfather_pr, 1); /* 流对准时, 肯定是对侧来包, 反向copy, 因为同向就不存在层数不一致了, reverse固定为1 */

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
#if USE_LINUX_KERNEL_HASH_ALGO	
		/* 2015-12-14 lijia add, 先通过第二个HASH值预先判断是否相等, 如果HASH不同, 地址肯定不同 */
		if(pshead_pr->hash_slave != psinsert_pr->hash_slave){
			phead=phead->phashnext;
			hash_list_num++;
			continue;
		}
#endif
		result=checkstreamorder(&plinkhead->stream, pshead_pr,psinsert_pr, &heap_streaminfo_skip_layer_num, &stack_streaminfo_skip_layer_num);
		if(result==0){
			res = phead;
			break;
		}

		phead=phead->phashnext;
		hash_list_num++;
	}

	if(unlikely(hash_list_num > local_sys_stat->count[SAPP_STAT_HASH_LIST_MAX])){
		local_sys_stat->count[SAPP_STAT_HASH_LIST_MAX] = hash_list_num;
	}

	if((res != NULL) && (stack_streaminfo_skip_layer_num > heap_streaminfo_skip_layer_num)){
		streaminfo_layer_alignment(&res->stream.stream_public, &res->stream, &pinsert->stream);
	}

	return res;
}



#if USE_LINUX_KERNEL_HASH_ALGO
extern int stream_make_hash(struct streaminfo_private *stream_pr, unsigned int maxsize);
#endif

#if USE_RBTREE_INSTEAD_LIST
extern void rb_sapp_insert(struct streamindex *new_sapp_node, struct rb_root *root);
extern struct streamindex *rb_sapp_search(struct streamindex *new_sapp_node, struct rb_root *rbroot, unsigned int hash_index);
extern  void rb_sapp_erase(struct streamindex *new_sapp_node, struct rb_root *root);


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
	struct rb_root *rb_root_table;

	if (STREAM_TYPE_TCP== stream_type)
	{
		rb_root_table = this_thread_stream->tcp_rb_root_table;
		hash_max=tcp_stream_table_size;
	}	
	else if(STREAM_TYPE_UDP==stream_type)
	{
		rb_root_table = this_thread_stream->udp_rb_root_table;
		hash_max=udp_stream_table_size;
	}

#if IOMODE_DPDK
	if(raw_pkt->hd_hash != 0){ /* 2016-05-05 lijia add, 底层硬件提供HASH */
		hash_index = raw_pkt->hd_hash % hash_max;;
	}
	else /* 软件计算HASH值 */
#endif

	{
#if USE_LINUX_KERNEL_HASH_ALGO
		hash_index=stream_make_hash(&(pindex->stream), (unsigned int)hash_max);
#else
		hash_index=mkstreamhash_new(&(pindex->stream), hash_max);
#endif	
	}

	if(NULL == rb_root_table[hash_index].rb_node){ /* 2015-12-14 lijia add, HASH表当前SLOT并没有流, 直接返回 */
		ptmp->hash_index = hash_index; /* 保存计算得到的HASH值 */
		return NULL;
	}

	a_index = rb_sapp_search(pindex, &rb_root_table[hash_index], hash_index);

	if (likely(a_index!=NULL)){
		pstream_pr = &(a_index->stream);
 		a_stream=&(pstream_pr->stream_public);
#if 0 /* 2014-12-18 */		
		if(a_stream->dirreverse==1)
#else
		if(pstream_pr->stream_dir != 1)
#endif
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
	struct streaminfo *ptmp = &pindex->stream.stream_public;
	UCHAR threadnum = ptmp->threadnum;
	struct rb_root *rb_root_table;
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[threadnum]->sys_stat;

	if (STREAM_TYPE_TCP==ptmp->type)
	 {
		rb_root_table = G_MESA_GLOBAL_STREAM[threadnum]->tcp_rb_root_table;
		local_sys_stat->count[SAPP_STAT_TCP_STREAM_NEW]++;
	 }	
	else if(STREAM_TYPE_UDP==ptmp->type)
    {
		rb_root_table = G_MESA_GLOBAL_STREAM[threadnum]->udp_rb_root_table;
   		local_sys_stat->count[SAPP_STAT_UDP_STREAM_NEW]++;
    } 
	 
	rb_sapp_insert(pindex, &rb_root_table[ptmp->hash_index]);	
}

void hash_del_stream(struct streamindex *pindex)
{
	struct streaminfo *ptmp = &pindex->stream.stream_public;
	UCHAR threadnum = ptmp->threadnum;
	struct rb_root *rb_root_table;
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[threadnum]->sys_stat;

	if (STREAM_TYPE_TCP==ptmp->type)
	 {
	 	rb_root_table = G_MESA_GLOBAL_STREAM[threadnum]->tcp_rb_root_table;
 	 	  local_sys_stat->count[SAPP_STAT_TCP_STREAM_DEL]++;
	 }	
	else if(STREAM_TYPE_UDP==ptmp->type)
    {
		rb_root_table = G_MESA_GLOBAL_STREAM[threadnum]->udp_rb_root_table;
   		local_sys_stat->count[SAPP_STAT_UDP_STREAM_DEL]++;
    } 
	 
	rb_sapp_erase(pindex, &rb_root_table[ptmp->hash_index]);	
}
#else
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

#if IOMODE_DPDK
	if(raw_pkt->hd_hash != 0){ /* 2016-05-05 lijia add, 底层硬件提供HASH */
		hash_index = raw_pkt->hd_hash % hash_max;
	}

	else /* 软件计算HASH值 */
#endif	

	{
#if USE_LINUX_KERNEL_HASH_ALGO
		hash_index=stream_make_hash(&(pindex->stream), (unsigned int)hash_max);
#else
		hash_index=mkstreamhash_new(&(pindex->stream), hash_max);
#endif	
	}


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
	
      //ptmp->hash_index=hash_index;

#if 0
     a_index= findandsethashindex(phashstream[hash_index],pindex);
#elif 0
	a_index=findandsethashindex_binsearch(elemcount,phashstream[hash_index],pindex);
#elif 0
	a_index= findandsethashindex_20141217(phashstream[hash_index],pindex, elemcount);
#else
	a_index = findandsethashindex_lru(phashstream[hash_index],pindex);
#endif

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
#if 0 /* 2014-12-18 */		
		if(a_stream->dirreverse==1)
#else
		if(pstream_pr->stream_dir != 1)
#endif
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
	 
	
#if 1 /* 放在HASH-Slot第一个位置 */
	   if(phashstream[hash_index]!=NULL)
		phashstream[hash_index]->phashprev=pindex;
	   pindex->phashnext=phashstream[hash_index];
	   phashstream[hash_index] = pindex;
#else
	 //adjust by lqy 20120803 在查找过程中已经确定了插入位置
	if(pindex->phashprev==NULL)
	{
		phashstream[pindex->stream.stream_public.hash_index] = pindex;
	}	
	else
	{	
		pindex->phashprev->phashnext=pindex;
	}
	if(pindex->phashnext!=NULL)
	    		pindex->phashnext->phashprev=pindex;
#endif	
	pelementcount[hash_index]++;


#if 0
static int listnum = 0;
if(pelementcount[pindex->hash_index] >= listnum){
	//printf("%s, ", printaddr(&pindex->stream.addr, pindex->stream.threadnum));
	printf("########### index:%d, list-num:%d\n", pindex->hash_index, pelementcount[pindex->hash_index]);
	listnum++;
}
#endif
	/*
		
	ptmindex=phashstream[pindex->hash_index] ;
	for(i=0;i<pelementcount[pindex->hash_index];i++)
	{
		assert(ptmindex!=NULL);
		if(ptmindex->hash_index !=pindex->hash_index)
		  assert(0);
		ptmindex=ptmindex->phashnext;
	}	
	*/

	pindex->stream.global_stream_id = get_global_stream_id(threadnum);
}


void hash_del_stream(struct streamindex *pindex)
{
	struct streamindex **phashstream;
	struct streaminfo_private *pstream_pr=&(pindex->stream);
	struct streaminfo *ptmp = &pstream_pr->stream_public;	
	unsigned short *pelementcount;
	UCHAR threadnum = ptmp->threadnum;
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[threadnum]->sys_stat;

	if(STREAM_TYPE_UDP==ptmp->type)
     {
         phashstream=G_MESA_GLOBAL_STREAM[threadnum]->udp_stream_table;
		pelementcount=G_MESA_GLOBAL_STREAM[threadnum]->udp_stream_talbe_hash_count;
		local_sys_stat->count[SAPP_STAT_UDP_STREAM_DEL]++;
		   if(ptmp->pudpdetail->clientpktnum+ptmp->pudpdetail->serverpktnum >= sapp_global_val->config.stream.udp.meaningful_statistics_minimum_pkt
			 && ptmp->pudpdetail->clientbytes+ptmp->pudpdetail->serverbytes >= sapp_global_val->config.stream.udp.meaningful_statistics_minimum_byte)
	       {		
			   if(ptmp->dir == DIR_DOUBLE)
			   {
				   local_sys_stat->count[SAPP_STAT_UDP_STREAM_DOUBLE]++;
				   local_sys_stat->count[SAPP_STAT_UDP_STREAM_DOUBLE_PKTS]+=(ptmp->pudpdetail->clientpktnum+ptmp->pudpdetail->serverpktnum);
				   local_sys_stat->count[SAPP_STAT_UDP_STREAM_DOUBLE_BYTES]+=(ptmp->pudpdetail->clientbytes+ptmp->pudpdetail->serverbytes);
			   }
			   else if(ptmp->dir == DIR_C2S)
			   {
				   local_sys_stat->count[SAPP_STAT_UDP_STREAM_C2S]++;
				   local_sys_stat->count[SAPP_STAT_UDP_STREAM_C2S_PKTS]+=(ptmp->ptcpdetail->clientpktnum + ptmp->ptcpdetail->serverpktnum);
				   local_sys_stat->count[SAPP_STAT_UDP_STREAM_C2S_BYTES]+=(ptmp->ptcpdetail->clientbytes + ptmp->ptcpdetail->serverbytes);
			   }
			   else if(ptmp->dir == DIR_S2C)
			   {
				   local_sys_stat->count[SAPP_STAT_UDP_STREAM_S2C]++;
				   local_sys_stat->count[SAPP_STAT_UDP_STREAM_S2C_PKTS]+=(ptmp->ptcpdetail->clientpktnum + ptmp->ptcpdetail->serverpktnum);
				   local_sys_stat->count[SAPP_STAT_UDP_STREAM_S2C_BYTES]+=(ptmp->ptcpdetail->clientbytes + ptmp->ptcpdetail->serverbytes);
			   }		
	     }
		   if(ptmp->dir == DIR_DOUBLE)
		   {
			   local_sys_stat->count[SAPP_STAT_UDP_STREAM_TOTAL_DOUBLE]++;
			   local_sys_stat->count[SAPP_STAT_UDP_STREAM_TOTAL_DOUBLE_PKTS] += (ptmp->pudpdetail->clientpktnum + ptmp->pudpdetail->serverpktnum);
			   local_sys_stat->count[SAPP_STAT_UDP_STREAM_TOTAL_DOUBLE_BYTES] += (ptmp->pudpdetail->clientbytes + ptmp->pudpdetail->serverbytes);
		   }
		   else if(ptmp->dir == DIR_C2S)
		   {
			   local_sys_stat->count[SAPP_STAT_UDP_STREAM_TOTAL_C2S]++;
			   local_sys_stat->count[SAPP_STAT_UDP_STREAM_TOTAL_C2S_PKTS] += (ptmp->ptcpdetail->clientpktnum + ptmp->ptcpdetail->serverpktnum);
			   local_sys_stat->count[SAPP_STAT_UDP_STREAM_TOTAL_C2S_BYTES] += (ptmp->ptcpdetail->clientbytes + ptmp->ptcpdetail->serverbytes);
		   }
		   else if(ptmp->dir == DIR_S2C)
		   {
			   local_sys_stat->count[SAPP_STAT_UDP_STREAM_TOTAL_S2C]++;
			   local_sys_stat->count[SAPP_STAT_UDP_STREAM_TOTAL_S2C_PKTS] += (ptmp->ptcpdetail->clientpktnum + ptmp->ptcpdetail->serverpktnum);
			   local_sys_stat->count[SAPP_STAT_UDP_STREAM_TOTAL_S2C_BYTES] += (ptmp->ptcpdetail->clientbytes + ptmp->ptcpdetail->serverbytes);
		   }		     
     }
	 else if (STREAM_TYPE_TCP==ptmp->type)
	 {
	 	const struct tcpdetail_private *pdetail_pr=(struct tcpdetail_private*)(ptmp->pdetail);
          phashstream=G_MESA_GLOBAL_STREAM[threadnum]->tcp_stream_table;
 		  pelementcount=G_MESA_GLOBAL_STREAM[threadnum]->tcp_stream_talbe_hash_count;
 		   local_sys_stat->count[SAPP_STAT_TCP_STREAM_DEL]++;

 		   if(pdetail_pr->has_lost_pkt_flag != 0){
				local_sys_stat->count[SAPP_STAT_TCP_LOST_PKT_STREAM_NUM]++;
 		   }
 		   
 		   if(ptmp->ptcpdetail->clientpktnum+ptmp->ptcpdetail->serverpktnum >= sapp_global_val->config.stream.tcp.meaningful_statistics_minimum_pkt
 		    && ptmp->ptcpdetail->clientbytes+ptmp->ptcpdetail->serverbytes >= sapp_global_val->config.stream.tcp.meaningful_statistics_minimum_byte)
           {
               if(ptmp->dir == DIR_DOUBLE)
               {
                   local_sys_stat->count[SAPP_STAT_TCP_STREAM_DOUBLE]++;
				   local_sys_stat->count[SAPP_STAT_TCP_STREAM_DOUBLE_PKTS]+=(ptmp->ptcpdetail->clientpktnum+ptmp->ptcpdetail->serverpktnum);
				   local_sys_stat->count[SAPP_STAT_TCP_STREAM_DOUBLE_BYTES]+=(ptmp->ptcpdetail->clientbytes+ptmp->ptcpdetail->serverbytes );
               }
               else if(ptmp->dir == DIR_C2S)
               {
                   local_sys_stat->count[SAPP_STAT_TCP_STREAM_C2S]++;
				   local_sys_stat->count[SAPP_STAT_TCP_STREAM_C2S_PKTS]+=(ptmp->ptcpdetail->clientpktnum+ptmp->ptcpdetail->serverpktnum);
				   local_sys_stat->count[SAPP_STAT_TCP_STREAM_C2S_BYTES]+=(ptmp->ptcpdetail->clientbytes+ptmp->ptcpdetail->serverbytes );
               }
               else if(ptmp->dir == DIR_S2C)
               {
                   local_sys_stat->count[SAPP_STAT_TCP_STREAM_S2C]++;
				   local_sys_stat->count[SAPP_STAT_TCP_STREAM_S2C_PKTS]+=(ptmp->ptcpdetail->clientpktnum+ptmp->ptcpdetail->serverpktnum);
				   local_sys_stat->count[SAPP_STAT_TCP_STREAM_S2C_BYTES]+=(ptmp->ptcpdetail->clientbytes+ptmp->ptcpdetail->serverbytes );
               }
               else
                   ;
           }
           
		   if(ptmp->dir == DIR_DOUBLE)
		   {
			   local_sys_stat->count[SAPP_STAT_TCP_STREAM_TOTAL_DOUBLE]++;
			   local_sys_stat->count[SAPP_STAT_TCP_STREAM_TOTAL_DOUBLE_PKTS] += (ptmp->ptcpdetail->clientpktnum + ptmp->ptcpdetail->serverpktnum);
			   local_sys_stat->count[SAPP_STAT_TCP_STREAM_TOTAL_DOUBLE_BYTES] += (ptmp->ptcpdetail->clientbytes + ptmp->ptcpdetail->serverbytes);
		   }
		   else if(ptmp->dir == DIR_C2S)
		   {
			   local_sys_stat->count[SAPP_STAT_TCP_STREAM_TOTAL_C2S]++;
			   local_sys_stat->count[SAPP_STAT_TCP_STREAM_TOTAL_C2S_PKTS] += (ptmp->ptcpdetail->clientpktnum + ptmp->ptcpdetail->serverpktnum);
			   local_sys_stat->count[SAPP_STAT_TCP_STREAM_TOTAL_C2S_BYTES] += (ptmp->ptcpdetail->clientbytes + ptmp->ptcpdetail->serverbytes);
		   }
		   else if(ptmp->dir == DIR_S2C)
		   {
			   local_sys_stat->count[SAPP_STAT_TCP_STREAM_TOTAL_S2C]++;
			   local_sys_stat->count[SAPP_STAT_TCP_STREAM_TOTAL_S2C_PKTS] += (ptmp->ptcpdetail->clientpktnum + ptmp->ptcpdetail->serverpktnum);
			   local_sys_stat->count[SAPP_STAT_TCP_STREAM_TOTAL_S2C_BYTES] += (ptmp->ptcpdetail->clientbytes + ptmp->ptcpdetail->serverbytes);
		   }
           
	 }else{
      	phashstream = NULL;
       	pelementcount = 0;
		assert(0);
     }
         
	 if(pindex->phashprev!=NULL)
	 {
	 	pindex->phashprev->phashnext=pindex->phashnext;
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
	/*
	//for test;
	ptmindex=phashstream[pindex->hash_index] ;
	for(i=0;i<pelementcount[pindex->hash_index];i++)
	{
		assert(ptmindex!=NULL);
                if(ptmindex->hash_index !=pindex->hash_index)
                  assert(0);
                ptmindex=ptmindex->phashnext;
	}
	*/

	/* 2014-10-15 lijia modify, 此处free后, 插件获取不到地址, 移动到tcp_free_stream()的最后面 */
	//free_heap_stream_info(pindex->stream.pfather);
}

#endif

void freeall_stream(int threadcount)
{
	struct global_stream *g_stream;
	struct stream_list *plist;
	struct streamindex *pindex;
	int i,j;
	for( i = 0; i < threadcount; i++)
	{
		  g_stream=G_MESA_GLOBAL_STREAM[i];
		  for(j=0;j<MAX_TCP_STATE;j++)
		 {
		 	plist=&(g_stream->tcpList[j]);
			while(plist->cnt>0)
			{
				pindex = plist->head;
				del_stream(pindex);
			}
		  }	
	  	  for(j=0;j<MAX_UDP_STATE;j++)
		 {
		 	plist=&(g_stream->udpList[j]);
			while(plist->cnt>0)
			{
				pindex = plist->head;
				del_stream(pindex);
			}
		  }

	}
	
	sleep(1);
	printf("All stream has been freed!\n");
//_exit(0);
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
			unsigned char tmp_mac_addr[ETH_ALEN];
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
#if 0
			dst_gtp->source = src_gtp->dest;
			dst_gtp->dest = src_gtp->source;
			dst_gtp->src_seq = src_gtp->dest_seq;
			dst_gtp->dest_seq = src_gtp->src_seq;
#endif			
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
        
		/* TODO 1:PPTP-addr */
		case ADDR_TYPE_PPTP:
		{
			const struct layer_addr_pptp *pptp_saddr = (const struct layer_addr_pptp *)saddr;
			struct layer_addr_pptp *pptp_daddr = (struct layer_addr_pptp *)daddr;
			pptp_daddr->C2S_call_id = pptp_saddr->C2S_call_id;
			pptp_daddr->S2C_call_id = pptp_saddr->S2C_call_id;
		}
		break;
		
		default:
			/* 其他地址类型, 如VLAN, L2TP等, 无方向性特征,直接copy */
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
	pstream_heap->addr.paddr = dictator_malloc(pstream_stack->threadnum, pstream_stack->addr.addrlen);
	if(0 == reverse){
		memcpy(pstream_heap->addr.paddr, pstream_stack->addr.paddr, pstream_stack->addr.addrlen);
	}else{
		addr_reverse_memcpy((const struct streaminfo_private *)pstream_stack, pstream_heap->addr.paddr, pstream_stack->addr.paddr, pstream_stack->addr.addrtype, pstream_stack->addr.addrlen);
	}
	
	return 0;
}

#if 0
void reverse_addr_new(void *addr, int addrtype)
{
	UINT16 tmp_ushort;
	UINT32 tmp_uint;
	
	switch(addrtype){
		case ADDR_TYPE_IPV4:
		//case __ADDR_TYPE_IP_PAIR_V4:
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

		case ADDR_TYPE_IPV6:
		//case __ADDR_TYPE_IP_PAIR_V6:
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
		
		case ADDR_TYPE_TCP:
		case ADDR_TYPE_UDP:
		{
			struct layer_addr_tcp *tcp_addr = (struct layer_addr_tcp *)addr;
			tmp_ushort = tcp_addr->source;
			tcp_addr->source =  tcp_addr->dest;
			tcp_addr->dest = tmp_ushort;
		}	
		break;

		case ADDR_TYPE_MAC: /* 2015-06-15 lijia add, 木马检测设备需求 */
		{
			struct layer_addr_mac *mac_addr = (struct layer_addr_mac *)addr;
			UCHAR tmp_mac[MAC_ADDR_LEN];
			memcpy(tmp_mac, mac_addr->src_mac, MAC_ADDR_LEN);
			memcpy(mac_addr->src_mac, mac_addr->dst_mac, MAC_ADDR_LEN);
			memcpy(mac_addr->dst_mac, tmp_mac, MAC_ADDR_LEN);
		}	
		break;

		default:
			/* 其他地址类型, 如VLAN, L2TP等, 无方向性特征, 无需转换 */
			return;
	}

	return;
}
#endif

void free_thread_stream(int thread_seq)
{
	struct global_stream *g_stream;
	struct stream_list *plist;
	struct streamindex *pindex;
	int j;
	
	  g_stream=G_MESA_GLOBAL_STREAM[thread_seq];
	  for(j=0;j<MAX_TCP_STATE;j++)
	 {
	 	plist=&(g_stream->tcpList[j]);
		while(plist->cnt>0)
		{
			pindex = plist->head;
			del_stream(pindex);
		}
	  }	
  	  for(j=0;j<MAX_UDP_STATE;j++)
	 {
	 	plist=&(g_stream->udpList[j]);
		while(plist->cnt>0)
		{
			pindex = plist->head;
			del_stream(pindex);
		}
	  }

#if HASH_COLLIDE_CALC
	printf("================ hash-collide-statistics =================\n");

	for(j = 0; j < HASH_COLLIDE_LIST_NUM_MAX; j++){
		printf("hash-collide-list-num:%d, \t times:%d\n", j, __hash_colliede_num[j]);
	}
	printf("================ hash-collide-statistics =================\n");
#endif

}

/* 2014-04-08 LiJia add */
void free_heap_stream_info(struct streaminfo *heap_stream, int layer)
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
		dictator_free(heap_stream->threadnum, addr->paddr);
		addr->paddr = NULL;
	}
	
	if(layer != 0){
		/* 流结构的最内层即第0层, 实际是通过malloc_and_copy_streamindex()获取的预先分配的内存,
			无需free, 
			pfather指向的streaminfo结构才是通过copy_stream_info_to_heap()动态malloc的.
		*/
		dictator_free(heap_stream->threadnum, heap_stream);	
	}
	return free_heap_stream_info((struct streaminfo *)pfather_pr, layer+1);
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


void update_opposite_addr_info(struct streaminfo_private *pstream_pr, 
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
                    //pstream_pr->stream_public.addr.gtp->source = p_stack->stream_public.addr.gtp->source;
                    //pstream_pr->stream_public.addr.gtp->src_seq = p_stack->stream_public.addr.gtp->src_seq;
                    pstream_pr->stream_public.addr.gtp->teid_c2s = p_stack->stream_public.addr.gtp->teid_c2s;
				}
				else{
                    //pstream_pr->stream_public.addr.gtp->dest = p_stack->stream_public.addr.gtp->source;
                    //pstream_pr->stream_public.addr.gtp->dest_seq = p_stack->stream_public.addr.gtp->src_seq;
                    pstream_pr->stream_public.addr.gtp->teid_s2c = p_stack->stream_public.addr.gtp->teid_c2s;
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
						sapp_runtime_log(RLOG_LV_INFO, "update_opposite_addr_info() error, current addrtype is ethernet, but pstream->addrtype is not ethernet!");
					}
				}
			break;
			
			default:	
				/* 其他协议层不涉及C2S, S2C两个方向地址非对称问题 */
				break;
		}
	}
	
	return update_opposite_addr_info((struct streaminfo_private *) pstream_pr->pfather_pr,
								 (struct streaminfo_private *) p_stack->pfather_pr, cur_dir);	
}


static inline raw_pkt_t *sapp_raw_pkt_dup(int thread_index, const raw_pkt_t *raw_pkt)
{
	int hdr_offset;
	
	raw_pkt_t *new_raw_pkt = (raw_pkt_t *)dictator_malloc(thread_index, sizeof(raw_pkt_t));
	memcpy(new_raw_pkt, raw_pkt, sizeof(raw_pkt_t));
	
	new_raw_pkt->__lib_raw_pkt_data = dictator_malloc(thread_index, raw_pkt->__lib_raw_pkt_len);
	memcpy((void *)(new_raw_pkt->__lib_raw_pkt_data), raw_pkt->__lib_raw_pkt_data, raw_pkt->__lib_raw_pkt_len);
	
	/* 更新raw_pkt_data指针 */
	hdr_offset = (char *)raw_pkt->raw_pkt_data - (char *)raw_pkt->__lib_raw_pkt_data;
	assert(hdr_offset <= 2048);	
	new_raw_pkt->raw_pkt_data = (char *)new_raw_pkt->__lib_raw_pkt_data + hdr_offset;

	return new_raw_pkt;
}


int update_polling_inject_context(struct streaminfo_private *pstream_pr, const raw_pkt_t *raw_pkt)
{
	int thread_index;

	if(0 == sapp_global_val->config.packet_io.polling_enabled){
		return 0;
	}

	thread_index = pstream_pr->stream_public.threadnum;
	/* 保存当前流C2S, S2C方向的第一个包 */
	if((DIR_ROUTE_DOWN & pstream_pr->stream_public.routedir) == DIR_ROUTE_DOWN){
		if(NULL == pstream_pr->polling_inject_context->raw_pkt_down){
			pstream_pr->polling_inject_context->raw_pkt_down = sapp_raw_pkt_dup(thread_index, raw_pkt);
		}
	}else{
		if(NULL == pstream_pr->polling_inject_context->raw_pkt_up){
			pstream_pr->polling_inject_context->raw_pkt_up = sapp_raw_pkt_dup(thread_index, raw_pkt);
		}
	}

	return 0;
}

int save_polling_inject_context(struct streaminfo_private *pstream_pr, const raw_pkt_t *raw_pkt)
{
	int thread_index;

	if(0 == sapp_global_val->config.packet_io.polling_enabled){
		return 0;
	}

	thread_index = pstream_pr->stream_public.threadnum;

	pstream_pr->polling_inject_context = (polling_inject_context_t *)dictator_malloc(thread_index, sizeof(polling_inject_context_t));
	memset(pstream_pr->polling_inject_context, 0, sizeof(polling_inject_context_t));

	if((DIR_ROUTE_DOWN & pstream_pr->stream_public.routedir) == DIR_ROUTE_DOWN){
		pstream_pr->polling_inject_context->raw_pkt_down = sapp_raw_pkt_dup(thread_index, raw_pkt);
	}else{
		pstream_pr->polling_inject_context->raw_pkt_up = sapp_raw_pkt_dup(thread_index, raw_pkt);
	}

	return 0;
}

static inline void sapp_raw_pkt_free(int thread_index, raw_pkt_t *raw_pkt)
{
	dictator_free(thread_index, (void *)raw_pkt->__lib_raw_pkt_data);
	dictator_free(thread_index, (void *)raw_pkt);
}

void free_polling_inject_context(struct streaminfo_private *pstream_pr)
{
	int thread_index;
	
	if(0 == sapp_global_val->config.packet_io.polling_enabled){
		return;
	}

	thread_index = pstream_pr->stream_public.threadnum;
	if(pstream_pr->polling_inject_context->raw_pkt_up){
		sapp_raw_pkt_free(thread_index, (raw_pkt_t *)pstream_pr->polling_inject_context->raw_pkt_up);
	}
	if(pstream_pr->polling_inject_context->raw_pkt_down){
		sapp_raw_pkt_free(thread_index, (raw_pkt_t *)pstream_pr->polling_inject_context->raw_pkt_down);
	}	

	dictator_free(thread_index, pstream_pr->polling_inject_context);
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
	unsigned long long glo_sid = 0;
	unsigned long long stream_seq; 
	unsigned long long relative_base_time;

	stream_seq = sapp_global_val->mthread_volatile[thread_seq]->stream_seq_per_thread++;
	relative_base_time = (sapp_global_val->individual_volatile->current_time - sapp_global_val->config.stream.stream_id_base_time_t) % RELATIVE_TIME_MAX;
	
	glo_sid = (thread_seq << 43) | (relative_base_time << 15) | (stream_seq);

	return glo_sid;
}

struct streaminfo_private *copy_stream_info_to_heap_single_layer(const struct streaminfo_private *stack_stream_pr, int reverse)
{
	struct streaminfo_private *heap_stream_pr = NULL;
	void *heap_addr;
	struct streaminfo *heap_stream;
	const struct streaminfo *stack_stream;
	struct streaminfo_private *pfather_pr;

	if(NULL == stack_stream_pr){
		return NULL;
	}

	stack_stream = &(stack_stream_pr->stream_public);

	heap_stream_pr = (struct streaminfo_private *)dictator_malloc(stack_stream->threadnum, sizeof(struct streaminfo_private));
	memcpy(heap_stream_pr, stack_stream_pr, sizeof(struct streaminfo_private));
	heap_stream = &(heap_stream_pr->stream_public);

	/* 单层streaminfo, pfather应该在外部调用者处理, 此处先设为NULL   */
	heap_stream_pr->pfather_pr = NULL;
	heap_stream_pr->stream_public.pfather = NULL;
			
	heap_addr = dictator_malloc(stack_stream->threadnum, stack_stream->addr.addrlen);
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
#if 0
struct streaminfo_private *copy_stream_info_to_heap(const struct streaminfo_private *stack_stream_pr, int reverse)
{
	struct streaminfo_private *heap_stream_pr = NULL;
	void *heap_addr;
	struct streaminfo *heap_stream;
	const struct streaminfo *stack_stream;
	struct streaminfo_private *pfather_pr;

	if(NULL == stack_stream_pr){
		return NULL;
	}

	stack_stream = &(stack_stream_pr->stream_public);

	heap_stream_pr = (struct streaminfo_private *)dictator_malloc(stack_stream->threadnum, sizeof(struct streaminfo_private));
	memcpy(heap_stream_pr, stack_stream_pr, sizeof(struct streaminfo_private));
	heap_stream = &(heap_stream_pr->stream_public);

	heap_stream_pr->pfather_pr = copy_stream_info_to_heap((const struct streaminfo_private *)stack_stream_pr->pfather_pr, reverse);
	pfather_pr = stack_stream_pr->pfather_pr;
	if((pfather_pr != NULL)
	  && (DEPOLYMENT_MODE_INLINE == sapp_global_val->config.packet_io.depolyment_mode_bin)
	  && (g_overlay_layer_set[pfather_pr->stream_public.addr.addrtype][pfather_pr->layer_index] != 0)){ /* 2021-01-11 lijia add, overlay层的pfather设为NULL, 插件不可见 */
		heap_stream->pfather = NULL;
	}else{
		heap_stream->pfather = (struct streaminfo *)heap_stream_pr->pfather_pr;
	}
			
	heap_addr = dictator_malloc(stack_stream->threadnum, stack_stream->addr.addrlen);
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
#else
struct streaminfo_private *copy_stream_info_to_heap(const struct streaminfo_private *stack_stream_pr, int reverse)
{
	struct streaminfo_private *heap_stream_pr;
	struct streaminfo *heap_stream;
	struct streaminfo_private *pfather_pr;

	if(NULL == stack_stream_pr){
		return NULL;
	}

	heap_stream_pr = copy_stream_info_to_heap_single_layer(stack_stream_pr, reverse);
	heap_stream = &heap_stream_pr->stream_public;

	heap_stream_pr->pfather_pr = copy_stream_info_to_heap(stack_stream_pr->pfather_pr, reverse);
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
#endif

int sapp_is_overlay_layer(const struct streaminfo_private *stream_pr, const raw_pkt_t *rawpkt)
{
	if(DEPOLYMENT_MODE_INLINE != sapp_global_val->config.packet_io.depolyment_mode_bin){
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
		if(plist->head){ /* polling阶段可能还没有流, 或者没有此状态的流, plist可能为NULL */
			ret = del_stream_by_time(plist, NULL);
			if(ret > 0){
				has_work = POLLING_STATE_WORK;
			}
		}
	}

	for(i = TCP_SYN_STATE; i < MAX_TCP_STATE; i++){
		plist=&(G_MESA_GLOBAL_STREAM[tid]->tcpList[i]);
		if(plist->head){ /* polling阶段可能还没有流, 或者没有此状态的流, plist可能为NULL */
			ret = del_stream_by_time(plist, NULL);
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


int sapp_dup_pkt_identify_udp_v4(int tid, struct streaminfo_private *pstream_pr, int tot_pkt, 
		const struct mesa_ip4_hdr *ipv4_hdr, const struct mesa_udp_hdr *udp_h)
{
	int is_dup_pkt = 0;
	sapp_dup_pkt_key_v4_t dup_bloom_key;

	if((0 == pstream_pr->has_duplicate_pkt) && (tot_pkt >= 3)){ //TODO, 只判断前N个包, 此处是否要通过配置文件指定？
		return 0;
	}
	
	sapp_get_dup_pkt_key_udp_v4(ipv4_hdr, udp_h, &dup_bloom_key);			
	is_dup_pkt = sapp_dup_pkt_identify_v4(tid, &dup_bloom_key);
	if(is_dup_pkt != 0){
		pstream_pr->has_duplicate_pkt = 1;
	}else{
		sapp_dup_pkt_mark_v4(tid, &dup_bloom_key);
	}

	return is_dup_pkt;
}

int sapp_dup_pkt_identify_udp_v6(int tid, struct streaminfo_private *pstream_pr, int tot_pkt, 
		const struct mesa_ip6_hdr *ipv6_hdr, const struct mesa_udp_hdr *udp_h)
{
	int is_dup_pkt = 0;
	sapp_dup_pkt_key_v6_t dup_bloom_key;

	if((0 == pstream_pr->has_duplicate_pkt) && (tot_pkt >= 3)){ //TODO, 只判断前N个包, 此处是否要通过配置文件指定？
		return 0;
	}
	
	sapp_get_dup_pkt_key_udp_v6(ipv6_hdr, udp_h, &dup_bloom_key); 		
	is_dup_pkt = sapp_dup_pkt_identify_v6(tid, &dup_bloom_key);
	if(is_dup_pkt != 0){
		pstream_pr->has_duplicate_pkt = 1;
	}else{
		sapp_dup_pkt_mark_v6(tid, &dup_bloom_key);
	}

	return is_dup_pkt;
}

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


int sapp_dup_pkt_identify_tcp(int tid, struct streaminfo_private *pstream_pr, int tot_pkt, 
		const void *ip_hdr, const struct mesa_tcp_hdr *tcp_h)
{
	int is_dup_pkt = 0;
	sapp_dup_pkt_key_v4_t dup_bloom_key_v4;
	sapp_dup_pkt_key_v6_t dup_bloom_key_v6;

	if((0 == pstream_pr->has_duplicate_pkt) && (tot_pkt >= SAPP_DUP_FIRST_PKT_NUM)){ //TODO, 只判断前N个包, 此处是否要通过配置文件指定？
		return 0;
	}

	if(ADDR_TYPE_IPV4 == pstream_pr->stream_public.addr.addrtype){
		sapp_get_dup_pkt_key_tcp_v4((struct mesa_ip4_hdr *)ip_hdr, tcp_h, &dup_bloom_key_v4);		
		is_dup_pkt = sapp_dup_pkt_identify_v4(tid, &dup_bloom_key_v4);
		if(is_dup_pkt != 0){
			pstream_pr->has_duplicate_pkt = 1;
		}else{
			sapp_dup_pkt_mark_v4(tid, &dup_bloom_key_v4); /* 如果不是重复包,加入bloom filter */
		}
	}else{
		sapp_get_dup_pkt_key_tcp_v6((struct mesa_ip6_hdr *)ip_hdr, tcp_h, &dup_bloom_key_v6);		
		is_dup_pkt = sapp_dup_pkt_identify_v6(tid, &dup_bloom_key_v6);
		if(is_dup_pkt != 0){
			pstream_pr->has_duplicate_pkt = 1;
		}else{
			sapp_dup_pkt_mark_v6(tid, &dup_bloom_key_v6); /* 如果不是重复包,加入bloom filter */
		}		
	}

	return is_dup_pkt;
}


#ifdef __cplusplus
}
#endif

