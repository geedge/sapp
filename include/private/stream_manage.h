#ifndef _STREAM_MANAGE_H_
#define _STREAM_MANAGE_H_ 

#include "stream_internal.h" 
#include "stream_register.h"
#include "timeout.h" 
#include "token_bucket.h"

#ifdef __cplusplus
extern "C" {
#endif

extern time_t g_CurrentTime;
extern int tcp_default_unorder;
extern unsigned short link_default_nopkt_time;

extern int tcp_creatlink_model;
extern int tcp_flood_detect_model;
extern int tcp_dataflood_pktlen;

extern int tcp_support_all;

#ifdef __cplusplus
}
#endif
	
#define TCP_CTEAT_LINK_BYSYN   0x01
#define TCP_CTEAT_LINK_BYDATA 0x02

#define TCP_FLOOD_DETECT_OFF 0x0
#define TCP_SYNFLOOD_DETECT_ON 0x01
#define TCP_DATAFLOOD_DETECT_ON 0x02

#define DROP             0x00
#define PASS             0x01
#define RETAIN             0x02

#define	SMART_OFFLOAD_FLAG_UNKNOWN	0x0
#define	SMART_OFFLOAD_FLAG_UDP 0x01
#define	SMART_OFFLOAD_FLAG_TCP 0x01
#define	SMART_OFFLOAD_FLAG_TCPALL 0x02


#define UNORDER_MAX_NUM  (tcp_default_unorder) 

//底层链接管理用状态定义
#define TCP_SYN_STATE    0
#define TCP_DATA_STATE   1
#define TCP_NOUSE_STATE  2
#define MAX_TCP_STATE	 3

#define UDP_ONE_STATE    0
#define UDP_TWO_STATE	 1
#define UDP_MORE_STATE   2
#define MAX_UDP_STATE	 3


#define STREAM_LINK_REUSE_BYSYN 0
#define STREAM_LINK_JUST_EST 1
#define STREAM_LINK_DATA 2
#define STREAM_LINK_CLOSE 3
#define STREAM_LINK_RESET 4
#define STREAM_LINK_TIMEOUT 5
#define STREAM_LINK_LRU_OUT	6
#define STREAM_FAKE_CLOSE_BY_DEPRIVE 7 /* 其他插件返回KILL_FOLLOW, KILL_OTHER后, 被强制CLOSE的插件状态 */
#define STREAM_CLOSE_BY_DUMPFILE_END 8  /* 2021-05-20 lijia add, for pcap dumpfile mode */


#define SINGLE_ACK_RECEVED_NO  0
#define SINGLE_ACK_RECEVED        1

struct stream_status{ /* 2014-03-31 lijia add */
	unsigned int tcp_num;
	unsigned int syn_cnt;
	unsigned int ack_cnt;
};

struct streamindex
{
	struct timeout timeout;
	struct streamindex *phashprev;
	struct streamindex *phashnext;
	struct streaminfo_private stream;
};


struct stream_list
{
	int cnt;
	int max_cnt;
	struct timeouts *streamindex_timer;
	long last_update_timer_s;
	long interval_to_next_timeout_s;
	timeout_error_t timer_error;
	struct token_bucket *timeout_ratelimiter;
};

struct stream_index_list_item
{
	struct streamindex index;
	STAILQ_ENTRY(stream_index_list_item) entries;
};

struct global_stream
{
	struct streamindex **tcp_stream_table;
	unsigned short  *tcp_stream_talbe_hash_count; /* lijia comment: 一个HASH_Slot下冲突链表元素个数 */
	struct stream_list tcpList[MAX_TCP_STATE];

	struct streamindex **udp_stream_table;
	unsigned short  *udp_stream_talbe_hash_count;/* lijia comment: 一个HASH_Slot下冲突链表元素个数 */
	struct stream_list udpList[MAX_UDP_STATE];

	STAILQ_HEAD(STREAM_INDEX_LIST,stream_index_list_item) freeList;
	struct stream_index_list_item *__freeList_real_head;
	int freeList_cnt;
	int freeList_max_cnt;

	struct timeouts *user_define_timer;
	long user_define_timer_cnt;
	long interval_to_next_timeout_s;
	timeout_error_t timer_error;
	struct token_bucket *tcp_timeout_ratelimiter;
	struct token_bucket *udp_timeout_ratelimiter;
	struct token_bucket *udp_opening_ratelimiter;
	struct token_bucket *tcp_opening_ratelimiter;
};

typedef struct _stStreamFunInfo
{
	struct timeout timeout;
	const struct streaminfo *pstream;
	int set_timer_s;
	int entry_id; /* 全局唯一的id, 用于每个插件入口函数的执行时间统计 */
	char pad[7];
	char appState;
	enum fun_type_t funtype;/* 2014-12-31 lqy add */
	char (*pfun)(void);
	void *pAppInfo;
	struct _stStreamFunInfo *next;
}StreamFunInfo;


#ifdef __cplusplus
extern "C" {
#endif

extern struct global_stream **G_MESA_GLOBAL_STREAM;
//extern struct thread_node_new *threads_pool_new;

struct streaminfo *findstream(struct streaminfo *ptmp);
void streamleavlist(struct streamindex *pindex,struct stream_list *plist);
void streamaddlist(struct streamindex *pindex,struct stream_list *plist);
struct streamindex *findstreamindex(struct streamindex *pindex, const raw_pkt_t *raw_pkt);
int lrustream(struct streamindex *pindex);
void hash_add_stream(struct streamindex *pindex);
void hash_del_stream(struct streamindex *pindex);

int stream_process_tcp(struct streaminfo *a_tcp, const void *, const void *,const raw_pkt_t * raw_pkt,void **apme,unsigned char *popstate);
int stream_process_tcp_allpkt(struct streaminfo *a_tcp,const void *, const void *,const raw_pkt_t * raw_pkt,void **apme,unsigned char *popstate);
//int stream_process_tcp_takeover(struct streaminfo *a_tcp,const raw_pkt_t * raw_pkt);
int stream_process_tcp_takeover(struct streaminfo *a_tcp,const void *iphdr);
int stream_process_udp(struct streaminfo *a_udp,const void *, const void *, const raw_pkt_t * raw_pkt,void **apme,unsigned char *popstate);
int stream_process_ipv4(struct streaminfo *pfstream,const struct ip *a_packet,int thread_num,unsigned char routedir,const raw_pkt_t *raw_pkt);
int stream_process_ipv6(struct streaminfo *pfstream,const struct ip6_hdr *a_packet,int thread_num,unsigned char routedir,const raw_pkt_t *raw_pkt);
int stream_process_ipv4_frag(struct streaminfo *pfstream,const struct ip *a_packet,int thread_num,unsigned char routedir,const raw_pkt_t *raw_pkt);
int stream_process_ipv6_frag(struct streaminfo *pfstream,const struct ip6_hdr *a_packet,int thread_num,unsigned char routedir,const raw_pkt_t *raw_pkt);
int stream_process_polling(int thread_seq);
int stream_process_arp(struct streaminfo *pfstream, const struct mesa_arp_hdr * this_layer_hdr, int thread_num,unsigned char routedir, const raw_pkt_t *raw_pkt);

//void freeall_stream(int threadcount);
void free_thread_stream(int thread_seq);
int dealipv4tcppkt(struct streamindex *pfstream,const struct mesa_ip4_hdr * a_packet,int thread_num,unsigned char routedir, const raw_pkt_t *raw_pkt,int);

struct streamindex *malloc_and_copy_streamindex(int threadnum, struct streamindex *pindex_stack);
void free_streamindex(int threadnum,struct streamindex *pindex);
int is_proxy_stream(const struct streaminfo *pstream);

int mkaddrhash(char *data,int datalen);
void wy_init_hash();
void udp_free_stream(struct streamindex *pstream);
int tcp_free_stream(struct streamindex *pstream, const void*, const void *,const raw_pkt_t *raw_pkt);
void update_opposite_addr_info(struct streaminfo_private *top_stream_pr, struct streaminfo_private *pstream_pr, 
							struct streaminfo_private *p_stack, unsigned char cur_dir);
int polling_stream_timeout(int tid);
int checkstreamorder(const struct streaminfo_private *top_stream_pr, struct streaminfo_private *pheap_stream_pr,
		struct streaminfo_private *pstack_stream_pr, int *heap_streaminfo_skip_layer_num, int *stack_streaminfo_skip_layer_num);
struct streaminfo_private *copy_stream_info_to_heap_single_layer(int mem_used_type, const struct streaminfo_private *stack_stream_pr, int reverse);

unsigned int sapp_jhash_4words(unsigned int a, unsigned int b, unsigned int c, unsigned int initval, unsigned int *out_val);


#ifdef __cplusplus
}
#endif

#endif
