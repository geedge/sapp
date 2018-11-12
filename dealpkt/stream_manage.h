#ifndef _STREAM_MANAGE_H_
#define _STREAM_MANAGE_H_ 

#include "stream_internal.h" 

#if USE_RBTREE_INSTEAD_LIST
#include "rbtree.h"
#endif

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

#define PASS             0x01
#define DROP             0x00
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

#define SINGLE_ACK_RECEVED_NO  0
#define SINGLE_ACK_RECEVED        1

struct stream_status{ /* 2014-03-31 lijia add */
	unsigned int tcp_num;
	unsigned int syn_cnt;
	unsigned int ack_cnt;
};

struct streamindex
{
	struct streamindex *prev;
	struct streamindex *next;
#if USE_RBTREE_INSTEAD_LIST
	struct rb_node rb;
#else
	struct streamindex *phashprev;
	struct streamindex *phashnext;
#endif	
	struct streaminfo_private stream;
};


struct stream_list
{
	struct streamindex *head; /* 删除淘汰从head开始, 即oldest */
	struct streamindex *tail; /* 新节点做为tail, 即newest */
	int cnt;
	int max_cnt;
	int sift_out_cnt;  //换出阈值
	int index;	//全局索引	
};

struct global_stream
{
#if USE_RBTREE_INSTEAD_LIST
	struct rb_root *tcp_rb_root_table;
#else
	struct streamindex **tcp_stream_table;
	unsigned short  *tcp_stream_talbe_hash_count; /* lijia comment: 一个HASH_Slot下冲突链表元素个数 */
#endif

	struct stream_list tcpList[MAX_TCP_STATE];

#if USE_RBTREE_INSTEAD_LIST
	struct rb_root *udp_rb_root_table;
#else
	struct streamindex **udp_stream_table;
	unsigned short  *udp_stream_talbe_hash_count;/* lijia comment: 一个HASH_Slot下冲突链表元素个数 */
#endif

	struct stream_list udpList[MAX_UDP_STATE];

	struct stream_list freeList;
};

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
int stream_process_ipv4(struct streaminfo *pfstream,const struct ip * a_packet,int thread_num,unsigned char routedir,const raw_pkt_t *raw_pkt);
int stream_process_ipv6(struct streaminfo *pfstream,const struct ip6_hdr *a_packet,int thread_num,unsigned char routedir,const raw_pkt_t *raw_pkt);
int stream_process_ipv4_frag(struct streaminfo *pfstream,const struct ip * a_packet,int thread_num,unsigned char routedir,const raw_pkt_t *raw_pkt);
int stream_process_ipv6_frag(struct streaminfo *pfstream,const struct ip6_hdr *a_packet,int thread_num,unsigned char routedir,const raw_pkt_t *raw_pkt);
int stream_process_polling(int thread_seq);
void freeall_stream(int threadcount);
void free_thread_stream(int thread_seq);
int dealipv4tcppkt(struct streamindex *pfstream,const struct mesa_ip4_hdr * a_packet,int thread_num,unsigned char routedir, const raw_pkt_t *raw_pkt,int);

struct streamindex *malloc_and_copy_streamindex(int threadnum, struct streamindex *pindex_stack);
void free_streamindex(int threadnum,struct streamindex *pindex);
int is_proxy_stream(const struct streaminfo *pstream);

int mkaddrhash(char *data,int datalen);
int wy_init_hash();
void udp_free_stream(struct streamindex *pstream);
void tcp_free_stream(struct streamindex *pstream, const void*, const void *,const raw_pkt_t *raw_pkt);
void update_opposite_addr_info(struct streaminfo_private *pstream_pr, 
	struct streaminfo_private *p_stack, unsigned char cur_dir);

#ifdef __cplusplus
}
#endif

#endif
