
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
#include "stream_internal.h"
#include "stream_manage.h"
#include "sysinfo.h"
#include "packet_io.h"
#include "packet_io_internal.h"
#include "project_requirement.h"
#include "project_internal.h"
#include "dictator.h"
#include <MESA/MESA_handle_logger.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/select.h>

#ifdef __cplusplus
extern "C" {
#endif

int Stream_Analyse_Process_Platform_version_VERSION_20181116; /* nm sapp | grep version */
int sapp_args_v = 20181116; /* ./sapp -v */

/* 
	下面的版本号用于packet_io_lib校验, 防止平台和dl.so不匹配导致运行异常, 或已修复的BUG未更新.
*/
#if IOMODE_PCAP
int sapp_packet_io_v = 20180808;
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
int sapp_packet_io_v = 20170512;
#elif IOMODE_SMITH
int sapp_packet_io_v = 20161027;
#elif IOMODE_DPDK_VXLAN
int sapp_packet_io_v = 20161101;
#elif IOMODE_PAG_MARSIO
int sapp_packet_io_v = 20170407;
#endif

int g_sapp_log_level = 20;
void *g_sapp_log_handle;

#define STREAM_ONCE_DEL_NUM 1000
void packet_io_status_stream_hash_update(int thread_seq, unsigned long hash_list_num);
void packet_io_status_stream_update(int tid, UCHAR stream_type, UCHAR stream_state,  int action);
static inline void update_stream_status(UCHAR threadnum, UCHAR type, UCHAR stream_state,  int action);
int project_requirement_global_init(void);
static inline void __do_streamleavlist(struct streamindex *pindex,struct stream_list *plist);

int tcp_stream_table_size=0;
int udp_stream_table_size=0;
//add by lqy 
unsigned short udp_reset_time=0;
unsigned short link_default_nopkt_time=0;
int tcpstate_num[MAX_TCP_STATE]={8000,2000,4000};
int udpstate_num[MAX_UDP_STATE]={2000,2000,2000};

int tcp_default_unorder=5;
int tcp_creatlink_model=TCP_CTEAT_LINK_BYSYN;
int tcp_flood_detect_model=TCP_FLOOD_DETECT_OFF;
int tcp_support_all=TCP_SUPPORT_ENTRYALL_OFF;
int tcp_dataflood_pktlen=5;
extern int g_packet_io_thread_num;
extern int g_reverse_ethernet_addr_sw;

struct global_stream **G_MESA_GLOBAL_STREAM;

//static struct stream_status stream_info[MAX_THREAD_NUM];

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
    g_stream->freeList.cnt= 	g_stream->freeList.max_cnt;
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

void udp_set_stream_timeout(unsigned short timeout)//2014-12-25 lijia add, 兼容旧平台, xj_fd
{
	udp_reset_time=(unsigned short)timeout;
}

void udp_set_stream_resettime(unsigned short timeout)
{
	udp_reset_time=(unsigned short)timeout;
}

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

	return 0;   
}

static struct streaminfo *del_stream(struct streamindex *pindex)
{
	struct streaminfo_private *pstream_pr=&(pindex->stream);
	struct streaminfo *pstream=&(pstream_pr->stream_public);
	
	if(STREAM_TYPE_UDP==pstream->type)
	{
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

#if DEBUG
	packet_io_status_stream_update(pstream->threadnum, pstream->type, pstream->stream_state, -1);	
#endif
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
#if DEBUG
	packet_io_status_stream_update(pstream->threadnum, pstream->type, pstream->stream_state, 1);	
#endif
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
			printf("Unknown addr type:%d!", this_stream->addr.addrtype);
			sapp_runtime_log(RLOG_LV_FATAL, "%s:%d: mkstreamhash_new() Unknown addr type:%d.\n", __FILE__, __LINE__, this_stream->addr.addrtype);	
			//assert(0);
			return -1;
		break;
	}

	return hash;
}
#endif

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
					struct streaminfo_private *pstack_stream_pr, unsigned short hash_elem_count)
{
	int ret;
	struct layer_addr *heap_addr, *stack_addr;

	heap_addr = &pheap_stream_pr->stream_public.addr;
	stack_addr = &pstack_stream_pr->stream_public.addr;

	if(pheap_stream_pr->stream_dir == pstack_stream_pr->layer_dir){
	/* 2015-07-15 lijia modify, 
		四元组比较使用哪类方式, 取决于HASH冲突率, 
		冲突率高时使用cmpaddr_positive()性能更好,
		否则使用memcmp()性能好.

		目前平台的HASH冲突率小于20%, 暂时使用memcmp().
	*/
		if(likely(hash_elem_count <= 2)){
			ret = memcmp(heap_addr->paddr,  stack_addr->paddr, heap_addr->addrlen);
		}else{
			ret = cmpaddr_positive(heap_addr->paddr,  stack_addr->paddr,
								heap_addr->addrtype, heap_addr->addrlen);
		}
	}else{
		/* 2015-03-04 lijia add, 反向地址比较, 无需先COPY.*/	
		ret = cmpaddr_reverse(heap_addr->paddr,  stack_addr->paddr,
							heap_addr->addrtype, heap_addr->addrlen);
	}
#if 0
printf("lijia debug: cmpaddr, addr_len:%d:\n", pst1->addr.addrlen);
int i;
printf("heap addr  \t :");
for(i = 0; i < pst1->addr.addrlen; i++){
printf("%02x,", ((UINT8 *)pst1->addr.paddr)[i]);
}
printf(" <-->\n");

printf("new stack addr:\t");
	for(i = 0; i < pst2->addr.addrlen; i++){
	printf("%02x,", ((UINT8 *)ptmp)[i]);
	}
printf("\n====================================================\n\n");
#endif
	
	if(0 == ret){
		//pst1->p_layer_header = pst2->p_layer_header;
		pheap_stream_pr->offset_to_raw_pkt_hdr = pstack_stream_pr->offset_to_raw_pkt_hdr;
	}

	return ret;
}

#endif

/*比较两个流结构体大小 */
//adjust 20140324 比较两个流结构是否相同，必须pfather 内的完全相同,
//递归比较两个流的父流的情况

/* lijia comment:
	pst1: in htable.
	pst2: new element;
	
	return value:
		0 : found, success;
		1 : pst1 > pst2;
		-1: pst1 < pst2
*/
int checkstreamorder(struct streaminfo_private *pheap_stream_pr,
		struct streaminfo_private *pstack_stream_pr, unsigned short hash_elem_count)
{
	int ret;
	//int isreverse=0;
	struct streaminfo *pheap_stream;
	struct streaminfo *pstack_stream;

	while(pheap_stream_pr!= NULL && pheap_stream_pr->addr_skip_for_layer_cmp == 1)
	{
		pheap_stream_pr = (struct streaminfo_private *)pheap_stream_pr->stream_public.pfather;
	}
	while(pstack_stream_pr != NULL && pstack_stream_pr->addr_skip_for_layer_cmp == 1)
	{
		pstack_stream_pr = (struct streaminfo_private *)pstack_stream_pr->stream_public.pfather;
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

	/* 2014-04-01 lijia add, 本层无需比较, 直接跳过 */
	if((0 == pheap_stream_pr->addr_use_as_hash) && (0 == pstack_stream_pr->addr_use_as_hash)){
		pheap_stream_pr->offset_to_raw_pkt_hdr = pstack_stream_pr->offset_to_raw_pkt_hdr;
		return checkstreamorder((struct streaminfo_private *)(pheap_stream->pfather), 
								(struct streaminfo_private *)(pstack_stream->pfather),
								hash_elem_count);
	}

	ret = cmpaddr_new(pheap_stream_pr, pstack_stream_pr, hash_elem_count);
	if(0 != ret){
		return ret;
	}else{
		/* 2015-03-11 lijia add, 需要将当前新IP层的包信息传递到流信息 */
		pheap_stream_pr->stream_public.addr.pktipfragtype = pstack_stream_pr->stream_public.addr.pktipfragtype;
	}
	
	ret=checkstreamorder((struct streaminfo_private *)(pheap_stream->pfather), 
						 (struct streaminfo_private *)(pstack_stream->pfather),
						 hash_elem_count);
	if(ret != 0)
	{
	   return ret;
	}
	
	return ret;
}

#if 0
static struct streamindex * findandsethashindex_20141217(struct streamindex *plinkhead,
			struct streamindex *pinsert, int hash_elem_count)
{
	struct streamindex *phead=plinkhead;
	struct streamindex  *res = NULL;
	struct streaminfo_private *pshead_pr=NULL;
	struct streaminfo_private *psinsert_pr=&(pinsert->stream);
	int result;
	unsigned long hash_list_num = 0;
	UCHAR threadnum = psinsert_pr->stream_public.threadnum;

	while(phead!=NULL)
	{  
		pshead_pr=&(phead->stream);	
#if USE_LINUX_KERNEL_HASH_ALGO	
		/* 2015-12-14 lijia add, 先通过第二个HASH值快速判断是否相等, 如果HASH不同, 地址肯定不同 */
		if(pshead_pr->hash_slave != psinsert_pr->hash_slave){
			phead=phead->phashnext;
			hash_list_num++;
			continue;
		}
#endif
		result=checkstreamorder(pshead_pr,psinsert_pr, hash_elem_count);
		if(result==0){
			//找到相同节点
			res = phead;
			break;
		}
		//prev=phead;

		phead=phead->phashnext;
		hash_list_num++;
	}

	if(unlikely(hash_list_num > g_SysInputInfo[threadnum][SYS_HASH_LIST_MAX])){
		g_SysInputInfo[threadnum][SYS_HASH_LIST_MAX] = hash_list_num;
	}

#if DEBUG
	packet_io_status_stream_hash_update(threadnum, hash_list_num+1);
#endif

	return res;
}
#endif

static struct streamindex * findandsethashindex_lru(struct streamindex *plinkhead,
			struct streamindex *pinsert, unsigned short hash_elem_count)
{
	struct streamindex *phead=plinkhead;
	struct streamindex  *res = NULL;
	struct streaminfo_private *pshead_pr=NULL;
	struct streaminfo_private *psinsert_pr=&(pinsert->stream);
	int result;
	unsigned long hash_list_num = 0;
	UCHAR threadnum = psinsert_pr->stream_public.threadnum;

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
		result=checkstreamorder(pshead_pr,psinsert_pr, hash_elem_count);
		if(result==0){
			res = phead;
			break;
		}
		//prev=phead;

		phead=phead->phashnext;
		hash_list_num++;
	}

	if(unlikely(hash_list_num > g_SysInputInfo[threadnum][SYS_HASH_LIST_MAX])){
		g_SysInputInfo[threadnum][SYS_HASH_LIST_MAX] = hash_list_num;
	}

#if DEBUG
	packet_io_status_stream_hash_update(threadnum, hash_list_num+1);
#endif

	return res;
}

#if 0
/*判断链表中是否有相应的链接信息
  如果没有，对可能的插入位置进行预设*/
struct streamindex * findandsethashindex(struct streamindex *plinkhead,struct streamindex *pinsert, int hash_elem_count)
{
    struct streamindex *phead=plinkhead;
    struct streamindex *prev=NULL;
    struct streaminfo_private *pshead=NULL;
	struct streaminfo_private *psinsert=&(pinsert->stream);
    int result;
    while(phead!=NULL)
    {
        pshead=&(phead->stream);
	result=checkstreamorder(pshead,psinsert,hash_elem_count);
	if(result>0)
	 {
	 	//在该节点前插入
	 	pinsert->phashprev=phead->phashprev;
		pinsert->phashnext=phead;
	 	return NULL;
	 }
	else if(result==0)
	{
		//找到相同节点
		return phead;
	}
	prev=phead;
	phead=phead->phashnext;
    }
    if(phead==NULL)
    {
       //在末尾插入
    	if(prev!=NULL)
    	{
    	    pinsert->phashprev=prev;
	    pinsert->phashnext=NULL;
    	}
    }
    return NULL;
}
#endif

#if 0
struct streamindex * findandsethashindex_binsearch(int elementcount,struct streamindex *plinkhead,
		struct streamindex *pinsert)
{
    struct streamindex *ptag=plinkhead;
    struct streaminfo_private *pshead=NULL;
    struct streaminfo_private *psinsert=&(pinsert->stream);
    int result=0;

    int high=elementcount-1;
    int low=0;
    int mid=0,i=0,itag=0;
   //空链表
   if(ptag==NULL){
   	return NULL;
   }
   //assert(plinkhead->hash_index==pinsert->hash_index);
   while(low<=high)
   {
       mid=low+(high-low)/2;
	 if(mid>=itag)
	    for(i=0;i<(mid-itag);i++) ptag=ptag->phashnext;
	else 
	   for(i=0;i<(itag-mid);i++) ptag=ptag->phashprev;
	itag=mid;
	
	//compare
	 pshead=&(ptag->stream);
#if 1 //2014-12-15 lqy modify
   	result=checkstreamorder(pshead,psinsert,elementcount);
#else
   	result=checkstreamorder(psinsert, pshead);
#endif
   	if(result==0) 		//找到相同节点
   	{
   		return ptag;
   	}
   
	if(result>0)
	  high=mid-1;
	else
	  low=mid+1;
   }

  if(low>high) //查找失败
  {
  	if(result>0)
  	{
 		//在该节点前插入
		pinsert->phashprev=ptag->phashprev;
		pinsert->phashnext=ptag;
  	}
	else
	{
		//在该节点后插入
		pinsert->phashprev=ptag;
		pinsert->phashnext=ptag->phashnext;
	}
  }
  /*
  if(pinsert->phashprev!=NULL)
   {
	assert(pinsert->phashprev->hash_index==pinsert->hash_index);
   }	
  if(pinsert->phashnext!=NULL)
   {
	assert(pinsert->phashnext->hash_index==pinsert->hash_index);
   }	
  */
  return NULL;
}
#endif

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

	if (STREAM_TYPE_TCP==ptmp->type)
	 {
	 	rb_root_table = G_MESA_GLOBAL_STREAM[threadnum]->tcp_rb_root_table;
 	 	  g_SysInputInfo[threadnum][SYS_TCP_LINK_NEW]++;
	 }	
	else if(STREAM_TYPE_UDP==ptmp->type)
         {
		rb_root_table = G_MESA_GLOBAL_STREAM[threadnum]->udp_rb_root_table;
   		g_SysInputInfo[threadnum][SYS_UDP_LINK_NEW]++;
         } 
	 
	rb_sapp_insert(pindex, &rb_root_table[ptmp->hash_index]);	
}

void hash_del_stream(struct streamindex *pindex)
{
	struct streaminfo *ptmp = &pindex->stream.stream_public;
	UCHAR threadnum = ptmp->threadnum;
	struct rb_root *rb_root_table;

	if (STREAM_TYPE_TCP==ptmp->type)
	 {
	 	rb_root_table = G_MESA_GLOBAL_STREAM[threadnum]->tcp_rb_root_table;
 	 	  g_SysInputInfo[threadnum][SYS_TCP_LINK_DEL]++;
	 }	
	else if(STREAM_TYPE_UDP==ptmp->type)
         {
		rb_root_table = G_MESA_GLOBAL_STREAM[threadnum]->udp_rb_root_table;
   		g_SysInputInfo[threadnum][SYS_UDP_LINK_DEL]++;
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
	a_index = findandsethashindex_lru(phashstream[hash_index],pindex, elemcount);
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

	if (STREAM_TYPE_TCP==ptmp->type)
	 {
                 phashstream=G_MESA_GLOBAL_STREAM[threadnum]->tcp_stream_table;
 	 	  pelementcount=G_MESA_GLOBAL_STREAM[threadnum]->tcp_stream_talbe_hash_count;
 	 	  g_SysInputInfo[threadnum][SYS_TCP_LINK_NEW]++;
	 }	
	else if(STREAM_TYPE_UDP==ptmp->type)
         {
                 phashstream=G_MESA_GLOBAL_STREAM[threadnum]->udp_stream_table;
	 	  pelementcount=G_MESA_GLOBAL_STREAM[threadnum]->udp_stream_talbe_hash_count;
   		g_SysInputInfo[threadnum][SYS_UDP_LINK_NEW]++;
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
}


void hash_del_stream(struct streamindex *pindex)
{
	struct streamindex **phashstream;
	struct streaminfo_private *pstream_pr=&(pindex->stream);
	struct streaminfo *ptmp = &pstream_pr->stream_public;	
	unsigned short *pelementcount;
	UCHAR threadnum = ptmp->threadnum;
	
	if(STREAM_TYPE_UDP==ptmp->type)
         {
                 phashstream=G_MESA_GLOBAL_STREAM[threadnum]->udp_stream_table;
		  pelementcount=G_MESA_GLOBAL_STREAM[threadnum]->udp_stream_talbe_hash_count;
		g_SysInputInfo[threadnum][SYS_UDP_LINK_DEL]++;
         }
	 else if (STREAM_TYPE_TCP==ptmp->type)
	 {
                 phashstream=G_MESA_GLOBAL_STREAM[threadnum]->tcp_stream_table;
 		  pelementcount=G_MESA_GLOBAL_STREAM[threadnum]->tcp_stream_talbe_hash_count;
 		   g_SysInputInfo[threadnum][SYS_TCP_LINK_DEL]++;
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
void addr_reverse_memcpy(void *daddr, const void *saddr, int addrtype, int addrlen)
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
			if (g_reverse_ethernet_addr_sw == 1)//2018-12-07 yw add, mac地址中包含信息时无需翻转
			{
				const struct layer_addr_mac *mac_saddr = (const struct layer_addr_mac *) saddr;
				struct layer_addr_mac *mac_daddr = (struct layer_addr_mac *) daddr;
				memcpy(mac_daddr->src_mac, mac_saddr->dst_mac, MAC_ADDR_LEN);
				memcpy(mac_daddr->dst_mac, mac_saddr->src_mac, MAC_ADDR_LEN);
			}
			else
			{
				memcpy(daddr, saddr, addrlen);
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

		case ADDR_TYPE_GPRS_TUNNEL:
		{
			const struct layer_addr_gtp *src_gtp = (const struct layer_addr_gtp *)saddr;
			struct layer_addr_gtp *dst_gtp = (struct layer_addr_gtp *)daddr;

			dst_gtp->source = src_gtp->dest;
			dst_gtp->dest = src_gtp->source;
			dst_gtp->src_seq = src_gtp->dest_seq;
			dst_gtp->dest_seq = src_gtp->src_seq;
		}
		break;

        case ADDR_TYPE_MPLS:
        {
            const struct layer_addr_mpls *src_mpls = (const struct layer_addr_mpls *)saddr;
            struct layer_addr_mpls *dst_mpls = (struct layer_addr_mpls *)daddr;

            memcpy(dst_mpls->src_mpls_pkt, src_mpls->dest_mpls_pkt, sizeof(src_mpls->dest_mpls_pkt));
            dst_mpls->src_mpls_layer_num = src_mpls->dest_mpls_layer_num;

            memcpy(dst_mpls->dest_mpls_pkt, src_mpls->src_mpls_pkt, sizeof(src_mpls->src_mpls_pkt));
            dst_mpls->dest_mpls_layer_num = src_mpls->src_mpls_layer_num;
        }
            break;
		/* TODO 1:PPTP-addr */
		
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
		addr_reverse_memcpy(pstream_heap->addr.paddr, pstream_stack->addr.paddr, pstream_stack->addr.addrtype, pstream_stack->addr.addrlen);
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
	struct streaminfo *pfather;
	struct layer_addr *addr;

	if(NULL == heap_stream){
		return;
	}

	pfather = heap_stream->pfather;
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
	return free_heap_stream_info(pfather, layer+1);
}

/* 2014-12-03 lijia add for sysinfo.log 
	args:
		action: 1:add; -1:del;
*/
static inline void update_stream_status(UCHAR threadnum, UCHAR stream_type, UCHAR stream_state,  int action)
{
	if(STREAM_TYPE_TCP == stream_type){
		switch(stream_state)
		{
			case TCP_DATA_STATE:
					g_SysInputInfo[threadnum][SYS_TCP_LINK_DATA] += action;
					break;
			case TCP_NOUSE_STATE:
					g_SysInputInfo[threadnum][SYS_TCP_LINK_NOUSE] += action;
					break;
			case TCP_SYN_STATE:
					g_SysInputInfo[threadnum][SYS_TCP_LINK_SYN] += action;
					break;					
		}	
	}else if(STREAM_TYPE_UDP == stream_type){
		switch(stream_state)
		{
			case UDP_TWO_STATE:
					g_SysInputInfo[threadnum][SYS_UDP_LINK_TWO] += action;
					break;
			case UDP_MORE_STATE:
					g_SysInputInfo[threadnum][SYS_UDP_LINK_MORE] += action;
					break;
			case UDP_ONE_STATE:
					g_SysInputInfo[threadnum][SYS_UDP_LINK_ONE] += action;
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



#if DEBUG
#include "iknow.h"
typedef struct{
	packet_io_status_base_t io_base_status; 
	unsigned long long total_search_times; /* 总HASH搜索数, 即调用了多少次findstreamindex() */
	unsigned long long total_hash_list_num; /* 总HASH冲突链表长度, (total_hash_list_num/total_search_times)即hash平均查找长度 */
	unsigned long long max_hash_list_num; /* 最大冲突链表数 */
}packet_io_status_stream_hash_t;

extern packet_io_status_t *g_packet_io_status_pool[MAX_THREAD_NUM];

static packet_io_status_stream_hash_t g_packet_io_status_stream_hash;

void *packet_io_status_stream_hash_mem_init(void)
{
	void *stream_hash_mem;
	
	stream_hash_mem = malloc(sizeof(packet_io_status_stream_hash_t));
	memset(stream_hash_mem, 0, sizeof(packet_io_status_stream_hash_t));

	return stream_hash_mem;
}


void packet_io_status_stream_hash_time_cb(void)
{
	int i;
	unsigned long long tmp_max_hlist_num = 0;
	packet_io_status_stream_hash_t *psh;

	g_packet_io_status_stream_hash.total_search_times = 0;
	g_packet_io_status_stream_hash.total_hash_list_num = 0;
	for(i = 0; i < g_packet_io_thread_num; i++){
		psh = (packet_io_status_stream_hash_t *)(g_packet_io_status_pool[i]->packet_io_status[IO_STATUS_STREAM_HASH]);
		g_packet_io_status_stream_hash.total_search_times += psh->total_search_times;
		g_packet_io_status_stream_hash.total_hash_list_num += psh->total_hash_list_num;
		if(psh->max_hash_list_num > tmp_max_hlist_num){
			tmp_max_hlist_num = psh->max_hash_list_num;
		}
	}	
	g_packet_io_status_stream_hash.max_hash_list_num = tmp_max_hlist_num;
}

static long ifuncb_show_stream_hash_summary(iknow_handle ihandle, iknow_conn iconn, const void *cb_fun_arg, const char *cmd_args)
{

	iprintf(ihandle, iconn, "stream hash summary:\ntotal-hash-search-num:%llu\ntotal-hash-list-num:%llu\nmax-hash-list-num:%llu\navg-hlist-num:%.2f",
		  g_packet_io_status_stream_hash.total_search_times,	
		  g_packet_io_status_stream_hash.total_hash_list_num,
		  g_packet_io_status_stream_hash.max_hash_list_num,
		  (float)g_packet_io_status_stream_hash.total_hash_list_num/(float)g_packet_io_status_stream_hash.total_search_times);

	return 0;
}

static long ifuncb_show_stream_hash_detail(iknow_handle ihandle, iknow_conn iconn, const void *cb_fun_arg, const char *cmd_args)
{
	int i;
	packet_io_status_stream_hash_t *psh;

	iprintf(ihandle, iconn, "stream hash detail:\n%10s %15s %13s %13s %13s\n", "thread-seq", "hash-search-num", "hash-list-num", "max-hlist-num", "avg-hlist-num");
	for(i = 0; i < g_packet_io_thread_num; i++){
		psh = (packet_io_status_stream_hash_t *)(g_packet_io_status_pool[i]->packet_io_status[IO_STATUS_STREAM_HASH]);
		iprintf(ihandle, iconn, "%10d %15llu %13llu %13llu %13.2f\n", 
		         i, psh->total_search_times, psh->total_hash_list_num, psh->max_hash_list_num,
		         (float)psh->total_hash_list_num/(float)psh->total_search_times);
	}	
		  

	return 0;
}

void iknow_register_stream_hash_cb(void *ihandle)
{
	int ret;

	ret = iknow_register_cmd(ihandle, "show stream summary", "display stream hash summary", ifuncb_show_stream_hash_summary, NULL, 0, NULL);
	assert(0 == ret);
	ret = iknow_register_cmd(ihandle, "show stream detail", "display stream hash detail", ifuncb_show_stream_hash_detail, NULL, 0, NULL);
	assert(0 == ret);		
}

void packet_io_status_stream_hash_update(int thread_seq, unsigned long hash_list_num)
{
	packet_io_status_stream_hash_t *psh;

	psh = (packet_io_status_stream_hash_t *)g_packet_io_status_pool[thread_seq]->packet_io_status[IO_STATUS_STREAM_HASH];

	psh->total_search_times++;
	psh->total_hash_list_num += hash_list_num;

	if(unlikely(hash_list_num > psh->max_hash_list_num)){
		psh->max_hash_list_num = hash_list_num;
	}
}

#endif



int get_stream_carry_tunnel_type(const struct streaminfo *this_stream, 
                         const struct streaminfo *upper_stream, unsigned short *tunnel_type)
{
	if(NULL == this_stream){
		return -1;
	}
	/* 父流的指针, 注意: sapp_online版和sapp_ip_port_union版不一致 */
	const struct streaminfo *pfather = this_stream->pfather; 
	
	switch(this_stream->addr.addrtype){
		case ADDR_TYPE_IPV4:
			pfather = this_stream->pfather;  /* IP-TCP/UDP被认为是一个整体, 更新pfather指针 */
			if(pfather != NULL){
				 if(__ADDR_TYPE_IP_PAIR_V4 == pfather->addr.addrtype){
				 	*tunnel_type = (unsigned short)STREAM_TUNNLE_IP_IN_IP;
				 }else if(__ADDR_TYPE_IP_PAIR_V6 == pfather->addr.addrtype){
					*tunnel_type = (unsigned short)STREAM_TUNNLE_4OVER6;
				 }else if(ADDR_TYPE_GRE == pfather->addr.addrtype){
				 	*tunnel_type = (unsigned short)STREAM_TUNNLE_GRE;
				 }
			} 
		break;
		
		case ADDR_TYPE_IPV6:
			pfather = this_stream->pfather;  /* IP-TCP/UDP被认为是一个整体, 更新pfather指针 */
			if(pfather != NULL){
				if(__ADDR_TYPE_IP_PAIR_V4 == pfather->addr.addrtype){
					*tunnel_type = (unsigned short)STREAM_TUNNLE_6OVER4;
				}else if((ADDR_TYPE_IPV4 == pfather->addr.addrtype)
				 && (STREAM_TYPE_UDP == pfather->type)){
					*tunnel_type = (unsigned short)STREAM_TUNNLE_TEREDO;
				}else if(ADDR_TYPE_GRE == pfather->addr.addrtype){
				 	*tunnel_type = (unsigned short)STREAM_TUNNLE_GRE;
				 }
			}
		break;

		case ADDR_TYPE_GRE:
			if((ADDR_TYPE_IPV4 == upper_stream->addr.addrtype)
			||((ADDR_TYPE_IPV6 == upper_stream->addr.addrtype))
			||(__ADDR_TYPE_IP_PAIR_V4 == upper_stream->addr.addrtype)
			||(__ADDR_TYPE_IP_PAIR_V6 == upper_stream->addr.addrtype)){
				*tunnel_type = (unsigned short)STREAM_TUNNLE_GRE;
			}
		break;

		case ADDR_TYPE_PPTP:
			/* pptp_entry()函数中已经将地址重置为ADDR_TYPE_PPTP, 肯定就是PPTP隧道 */
			*tunnel_type = (unsigned short)STREAM_TUNNLE_PPTP;
		break;

		case ADDR_TYPE_L2TP:
			/* l2tp_entry()函数中已经将地址重置为ADDR_TYPE_L2TP, 肯定就是L2TP隧道 */
			*tunnel_type = (unsigned short)STREAM_TUNNLE_L2TP;
		break;

	}

	return get_stream_carry_tunnel_type(pfather, this_stream, tunnel_type);
}


void update_opposite_addr_info(struct streaminfo_private *pstream_pr, 
	struct streaminfo_private *p_stack, unsigned char cur_dir)
{
	if(pstream_pr == NULL || p_stack == NULL)
	{
		return;
	}
	if(p_stack->need_update_opposite_addr == 0) {
		return update_opposite_addr_info((struct streaminfo_private *) pstream_pr->stream_public.pfather,
		                             (struct streaminfo_private *) p_stack->stream_public.pfather, cur_dir);
	} else{
		switch(p_stack->stream_public.addr.addrtype)
		{
			case ADDR_TYPE_GPRS_TUNNEL:
				    /* GTP地址C2S, S2C方向独立, 无法靠当前包地址区分dir, 每次栈里的变量都存储于source方向, 即C2S方向,  
				       创建流时, 已经根据最内层TCP, UDP的流方向, 将GTP的地址存于source或dest, 
				       此函数是更新的对端缺失的地址, 仅靠最内层的cur_dir表示需要更新哪个方向的地址, 固定从当前包的source拷贝. 
				     */
				if(cur_dir == DIR_C2S){
                    pstream_pr->stream_public.addr.gtp->source = p_stack->stream_public.addr.gtp->source;
                    pstream_pr->stream_public.addr.gtp->src_seq = p_stack->stream_public.addr.gtp->src_seq;
				}
				else{
                    pstream_pr->stream_public.addr.gtp->dest = p_stack->stream_public.addr.gtp->source;
                    pstream_pr->stream_public.addr.gtp->dest_seq = p_stack->stream_public.addr.gtp->src_seq;
				}
				break;
			case ADDR_TYPE_MPLS:
				if(sapp_global_single.create_mpls_anyway != 0){
					if(cur_dir == DIR_C2S){
						memcpy(pstream_pr->stream_public.addr.mpls->src_mpls_pkt,
						        p_stack->stream_public.addr.mpls->src_mpls_pkt,
						        sizeof(p_stack->stream_public.addr.mpls->src_mpls_pkt));
	                    pstream_pr->stream_public.addr.mpls->src_mpls_layer_num = p_stack->stream_public.addr.mpls->src_mpls_layer_num;
					}
					else{
	                    memcpy(pstream_pr->stream_public.addr.mpls->dest_mpls_pkt,
	                           p_stack->stream_public.addr.mpls->src_mpls_pkt,
	                           sizeof(p_stack->stream_public.addr.mpls->src_mpls_pkt));
	                    pstream_pr->stream_public.addr.mpls->dest_mpls_layer_num = p_stack->stream_public.addr.mpls->src_mpls_layer_num;
					}
				}
				break;
			default:
				return update_opposite_addr_info((struct streaminfo_private *) pstream_pr->stream_public.pfather,
				                             (struct streaminfo_private *) p_stack->stream_public.pfather, cur_dir);			
				break;
		}
	}
	return;
}


#ifdef __cplusplus
}
#endif

