#ifndef _IP_REASSEMBLY_H_
#define _IP_REASSEMBLY_H_

#include "stream_internal.h" 


#define USE_MESA_STREAM_HASH			(1) /* 使用基于隧道模式新的HASH表 */	
#if USE_MESA_STREAM_HASH
#include "MESA_htable.h"
#endif

#define IP_FRAG_DEFAULT_BUF_SIZE		(2048) /* 预留的默认IP分片重组缓冲区大小, 通过统计得出, 重组后的IP包长度小于2KB的占90%以上 */

#define IP_FRAG_OK					(0x00)	/* 检测正常 */
#define IP_FRAG_INVALID_PACKET			(0x10)	/* 无效分片包，此分片包不再处理，但继续处理同一IPQ的下一个分片包 */
#define IP_FRAG_DISCARD				(0x08)	/* 攻击分片包，立即释放整个IPQ队列 */
#define IP_FRAG_IGNORE					(0x04)	/* 攻击分片包，以后同一IPQ队列的分片包都不再处理，但不清除IPQ，直至超时 */

#define IP_FRAG_FIRST_IN              		(0x02)	/* 已收到了第一个分片包 */
#define IP_FRAG_LAST_IN               		(0x01)	/* 已收到了最后一个分片包 */


struct addr_list{
	struct layer_addr addr;
	struct addr_list *next;
};


/* 一个分片包 */
struct ip_frags{
	int offset;				/* 此分片包第一个字节相对原始包的偏移量 */
	int end;            	/* 此分片包最后一个字节相对原始包的偏移量 */
	struct ip_frags *next;	/* 此分片包在分片链表中的后继节点 */
	struct ip_frags *prev;	/* 此分片包在分片链表中的前驱节点 */
};


/* 分片重组队列 */
struct frag_ipq{
	int buf_size; 		/* 新IP包缓存的长度 */
	short last_in; 		/* 标志位，收到第一个包或最后一个包 */
	short attack_flag;  /* 标志位，是否检测到恶意攻击数据包 */
	int tot_len; 		/* 当前收到分片包的最大偏移量 */
	int meat;			/* 实际收到的IP分片包有效数据长度 */
	unsigned int hash_index; 	/* 保存计算出的HASH值，以后重复使用，无需再次计算 */
	int hash_key_size;
	int private_len;	/* 与协议密切相关的独立参数长度 */
	int frags_num;		/* 收到的分片包个数 */
	time_t create_time; /* ipq建立时间，即收到第一个分片包的时间 */
	void *new_iph; 		/* 重组后的新IP包头部指针 */
	struct ip_frags *fragments;			/* 分片包链表头 */
	struct ip_frags *fragments_tail;	/* 分片包链表尾 */
#if USE_MESA_STREAM_HASH
	int thread_num;	/* 使用新HASH时, thread_num不好传递, 放于此结构内 */
#else
	struct frag_ipq *hash_prev;  		/* HASH冲突链表的前驱节点 */
	struct frag_ipq *hash_next;  		/* HASH冲突链表的后继节点 */
	struct frag_ipq *lru_prev;  		/* LRU链表的前驱节点 */
	struct frag_ipq *lru_next;  		/* LRU链表的后继节点 */
#endif	
	void *hash_key; /* hash key，与协议无关，由公共模块申请空间，长度由hash_key_size指定 */
	void *private_info; 	/* 与协议密切相关的独立参数，需自行申请空间, 长度由private_len指定 */
	raw_ipfrag_list_t *ipfrag_list; /* 暂时存储所有原始分片包 */
};


/* 分片重组的管理结构，与具体协议版本无关 */
struct frag_manage{
	int thread_num;					/* 线程ID */
	unsigned int total_mem;			/* 当前占用内存总量 */
#if USE_MESA_STREAM_HASH
	MESA_htable_handle frag_hash_table;
#else
	unsigned int hash_table_size;	/* HASH表大小 */
	int __pad__;
	struct frag_ipq **frag_hash_table;					/* HASH表头指针 */
	unsigned int (*hash_index)(void *hash_key);			/* HASH函数指针 */
	int (*hash_cmp)(void *hash_key1, void *hash_key2);	/* key比较函数指针 */
	struct frag_ipq *lru_head;	/* lru链表头 */
	struct frag_ipq *lru_tail;	/* lru链表尾 */
#endif	
};

#define JHASH_INITVAL        0xdeadbeef
#define JHASH_INITVAL2       0xfeedcade

#ifdef __cplusplus
extern "C" {
#endif

unsigned int frag_common_hash(unsigned int a, unsigned int b, unsigned int c, unsigned int initval) ;

void *frag_malloc(struct frag_manage *handle, int size);
void frag_free(struct frag_manage *handle, void *free_p, int size);
struct ip_frags* frags_create(struct frag_manage *handle, int offset, int end);
void frags_kill(struct frag_manage *handle, struct frag_ipq *ipq, struct ip_frags *frags_del);
struct frag_ipq* frag_ipq_find(struct frag_manage *handle, void *key, int key_size);
#if USE_MESA_STREAM_HASH
struct frag_ipq* frag_ipq_create(int thread_num);
#else
struct frag_ipq* frag_ipq_create(struct frag_manage *handle, void *key, int key_size, unsigned int hash_index);
#endif
void frag_ipq_kill(struct frag_manage *handle, struct frag_ipq *ipq);
void frag_add_lru_node (struct frag_manage *handle, struct frag_ipq *new_node);
void frag_del_lru_node (struct frag_manage *handle, struct frag_ipq *del_node);
void frag_lru_update(struct frag_manage *handle, struct frag_ipq *ipq);
void frag_add_hash_node (struct frag_manage *handle, struct frag_ipq *new_node);
void frag_del_hash_node (struct frag_manage *handle, struct frag_ipq *del_node);
void *frag_reassemble(struct frag_manage *handle, struct frag_ipq *ipq);

int frags_list_append(struct frag_ipq *ipq, const raw_pkt_t *raw_pkt, int type, int tid);
void raw_frags_list_free_global(int tid, int type);
void raw_frags_list_free_stream(int thread_num, struct streaminfo *stream);
raw_ipfrag_list_t *frags_list_merge(raw_ipfrag_list_t *new_merge_list, raw_ipfrag_list_t *old_list);
void __frags_list_check(raw_ipfrag_list_t *frags_list);
int MESA_stream_list_cmp(struct streaminfo_private *stream1, struct streaminfo_private *stream2);
void MESA_stream_list_free(int mem_used_type, struct streaminfo_private *heap_stream);
struct streaminfo_private *MESA_stream_list_dup(int mem_used_type, struct streaminfo_private *stack_stream, int reverse);

#ifdef __cplusplus
}
#endif


#endif
