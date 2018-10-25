/*
 *  Description:
 *      IP分片重组的公共函数，与协议版本无关,
 *		与IPv4或IPv6协议密切相关的函数，请在此基础上再次封装.
 *
 *  Author:    Li Jia<lijia@software.ict.ac.cn>
 *  Date:      2012-06-06
 *  Version:   0.1
 */
#include "compat.h"
#include "ip_reassembly.h"
#include "stream_internal.h" 
#include "project_requirement.h"
#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#ifdef __cplusplus
extern "C" {
#endif


extern void raw_frags_list_free_one(int thread_num, void *);
extern time_t g_CurrentTime;


/* 申请size大小的一块内存，同时更新总内存占用值 */
void *frag_malloc(struct frag_manage *handle, int size)
{
	void *p = dictator_malloc(handle->thread_num, size);

	handle->total_mem += size;

	return p;
}


/* 需要额外传递free的指针所指向内存块的大小，用于统计内存占用值 */
void frag_free(struct frag_manage *handle, void *free_p, int size)
{
	dictator_free(handle->thread_num, free_p);
	handle->total_mem -= size;

	return;
}

#if (USE_MESA_STREAM_HASH==0)

/* 将一个新ipq结构插入LRU链表 */
void frag_add_lru_node (struct frag_manage *handle, struct frag_ipq *new_node) 
{
	/* 新节点插在链表尾 */
	if(handle->lru_tail)
	{
		handle->lru_tail->lru_next = new_node;
		new_node->lru_prev = handle->lru_tail;
		new_node->lru_next = NULL;
		handle->lru_tail = new_node;
	}
	else /* 第一个节点 */
	{
		new_node->lru_next = NULL;
		new_node->lru_prev = NULL;
		handle->lru_tail = new_node;
		handle->lru_head = new_node;
	}
}


/* 将一个ipq结构从LRU链表中删除 */
void frag_del_lru_node (struct frag_manage *handle, struct frag_ipq *del_node) 
{
	if(del_node->lru_prev)
	{
		del_node->lru_prev->lru_next = del_node->lru_next;
	}
	else /* 当前节点为链表头 */
	{
		handle->lru_head = del_node->lru_next;
	}

	if(del_node->lru_next)
	{
		del_node->lru_next->lru_prev = del_node->lru_prev;
	}
	else /* 当前节点为链表尾 */
	{
		handle->lru_tail = del_node->lru_prev;
	}
}


/* 对ipq结构做LRU更新，实际就是从链表中取出来，再放至LRU链表尾.*/
void frag_lru_update(struct frag_manage *handle, struct frag_ipq *ipq)
{
	frag_del_lru_node(handle, ipq);
	frag_add_lru_node(handle, ipq);
}


/* 将一个新ipq结构插入HASH表 */
void frag_add_hash_node (struct frag_manage *handle, struct frag_ipq *new_node)
{
	struct frag_ipq *tmp = NULL;
	unsigned int hash_index = new_node->hash_index;/* HASH值在frag_ipq_find()中已经计算过 */

	for(tmp = handle->frag_hash_table[hash_index]; tmp; tmp = tmp->hash_next)
	{
		if(handle->hash_cmp(tmp->hash_key, new_node->hash_key) == 0)
		{
			break;
		}
	}

	if(tmp != NULL) /* already exist */
	{
		return;
	}

	/* 新节点，放在HASH-SLOT第一个节点 */
	new_node->hash_next = handle->frag_hash_table[hash_index];
	new_node->hash_prev = NULL;
	
	if(handle->frag_hash_table[hash_index])
	{
		handle->frag_hash_table[hash_index]->hash_prev = new_node;
	}
	
	handle->frag_hash_table[hash_index] = new_node;

	return;
}


/* 将一个ipq结构从HASH表中删除 */
void frag_del_hash_node (struct frag_manage *handle, struct frag_ipq *del_node)
{
	unsigned int hash_index = del_node->hash_index;

	if(del_node->hash_prev)
	{
		del_node->hash_prev->hash_next = del_node->hash_next;
	}
	else /* HASH-slot中第一个节点 */
	{
		handle->frag_hash_table[hash_index] = del_node->hash_next;
	}

	if(del_node->hash_next)
	{
		del_node->hash_next->hash_prev = del_node->hash_prev;
	}
}
#endif

/* 创建一个新的分片结构，同时记录此分片的offset和end值 */
struct ip_frags* frags_create(struct frag_manage *handle, int offset, int end)
{
	struct ip_frags *frags = (struct ip_frags *)frag_malloc(handle, sizeof(struct ip_frags));

	memset(frags, 0, sizeof(struct ip_frags));

	frags->offset = offset;
	frags->end = end;

	return frags;
}


/* 从IPQ链表中删除一个IP分片结构 */
void frags_kill(struct frag_manage *handle, struct frag_ipq *ipq, struct ip_frags *frags_del)
{
	if(frags_del->prev) 
	{
    	frags_del->prev->next = frags_del->next;
	} 
	else 
	{
		ipq->fragments = frags_del->next;
	}
	
	if(frags_del->next) 
	{
    	frags_del->next->prev = frags_del->prev;
	}
	else
	{
		ipq->fragments_tail = frags_del->prev;
	}

	frag_free(handle, frags_del, sizeof(struct ip_frags));
}

#if USE_MESA_STREAM_HASH
/*
	|-------------------buf_size ----------------------|
	|---first ip hdr len --| --- ip frags total len ---|

	buf_size内存分为两段, 第一个分片包的原始头部和总的分片数据长度之和.
*/
struct frag_ipq* frag_ipq_create(int thread_num)
{
	struct frag_ipq *ipq;

	ipq = (struct frag_ipq *)dictator_malloc(thread_num, sizeof(struct frag_ipq));
	memset(ipq, 0, sizeof(struct frag_ipq));

	ipq->thread_num = thread_num;

	/* 为新IP包分配空间, 初始大小为2048字节 */
	ipq->new_iph = dictator_malloc(thread_num, IP_FRAG_DEFAULT_BUF_SIZE);
	ipq->buf_size = IP_FRAG_DEFAULT_BUF_SIZE;

	ipq->create_time = g_CurrentTime;

	return ipq;
}
#else
/* 创建一个新的分片重组队列 */
struct frag_ipq* frag_ipq_create(struct frag_manage *handle, void *key_stack, 
									 int key_size, unsigned int hash_index)
{
	struct frag_ipq *ipq;
	void *key_heap;

	ipq = (struct frag_ipq *)frag_malloc(handle, sizeof(struct frag_ipq));
	memset(ipq, 0, sizeof(struct frag_ipq));

	key_heap = frag_malloc(handle, key_size);
	memcpy(key_heap, key_stack, key_size);

	ipq->hash_key = key_heap;
	ipq->hash_key_size = key_size;
	
	ipq->hash_index = hash_index;

	/* 为新IP包分配空间, 初始大小为2048字节 */
	ipq->new_iph = frag_malloc(handle, IP_FRAG_DEFAULT_BUF_SIZE);
	ipq->buf_size = IP_FRAG_DEFAULT_BUF_SIZE;

	ipq->create_time = g_CurrentTime;
	
	frag_add_lru_node(handle, ipq);
	frag_add_hash_node(handle, ipq);

	return ipq;
}
#endif


#if USE_MESA_STREAM_HASH==0
/* 完全删除一个ipq结构，释放所有的内存资源 */
void frag_ipq_kill(struct frag_manage *handle, struct frag_ipq *ipq)
{
	struct ip_frags *frag, *next;
	
	frag_del_lru_node(handle, ipq);
	frag_del_hash_node(handle, ipq);

	/* Release all fragment data. */
	frag = ipq->fragments;
	while(frag != NULL) 
	{
    		next = frag->next;
    		frag_free(handle, frag, sizeof(struct ip_frags));
		frag = next;
	}

	frag_free(handle, ipq->new_iph, ipq->buf_size);
	frag_free(handle, ipq->hash_key, ipq->hash_key_size);

	if(ipq->private_info && ipq->private_len)
	{
		frag_free(handle, ipq->private_info, ipq->private_len);
	}
#if (0 == HIGH_PERF)
	raw_frags_list_free_one(handle->thread_num, ipq->ipfrag_list);
#endif	
	ipq->ipfrag_list = NULL;

	frag_free(handle, ipq, sizeof(struct frag_ipq));

	return;
}
#endif

#if (USE_MESA_STREAM_HASH==0)
/* 根据参数key，找到此分片包所属的ipq队列 */
struct frag_ipq* frag_ipq_find(struct frag_manage *handle, void *key, int key_size)
{
	uint32 hash_index;
	struct frag_ipq *ipq = NULL;

	hash_index = handle->hash_index(key) % handle->hash_table_size;

	for(ipq = handle->frag_hash_table[hash_index]; ipq != NULL; ipq = ipq->hash_next)
	{
		if(handle->hash_cmp(ipq->hash_key, key) == 0)
		{
			return ipq;
		}
	}

	/* 找不到对应ipq结构的话，则新建ipq结构，并把hash_index做为一个参数，
	   传递给frag_ipq_create(), 避免插入HASH表时，再次计算一遍HASH值. 
	*/
	if(NULL == ipq)
	{
		return frag_ipq_create(handle, key, key_size, hash_index);
	}

	return ipq;
}
#endif

/*
	收到所有的分片包后，将其重组成一个完整的原始包，并释放占用的其他额外内存资源.
	返回值: 原始IP包头指针
*/
#if USE_MESA_STREAM_HASH
void *frag_reassemble(struct frag_manage *handle, struct frag_ipq *ipq)
{
	void *new_iph;

	new_iph = ipq->new_iph;

	/* 这里只更新内存占用值，实际的内存free操作在上层模块处理完之后 */
	handle->total_mem -= ipq->buf_size;

	return new_iph;
}
#else
void *frag_reassemble(struct frag_manage *handle, struct frag_ipq *ipq)
{
	void *new_iph;
	struct ip_frags *frag, *next;
	
	frag_del_lru_node(handle, ipq);

	frag_del_hash_node(handle, ipq);

	/* Release all fragments data. */
	frag = ipq->fragments;
	while(frag != NULL) 
	{
    		next = frag->next;
    		frag_free(handle, frag, sizeof(struct ip_frags));
		frag = next;
	}

	new_iph = ipq->new_iph;

	/* 这里只更新内存占用值，实际的内存free操作在上层模块处理完之后 */
	handle->total_mem -= ipq->buf_size;
	
	frag_free(handle, ipq->hash_key, ipq->hash_key_size);
	if(ipq->private_info && ipq->private_len)
	{
		frag_free(handle, ipq->private_info, ipq->private_len);
	}
	frag_free(handle, ipq, sizeof(struct frag_ipq));

	return new_iph;
}
#endif

static inline unsigned int rol32(unsigned int word, unsigned int shift) 
{
	return (word << shift) | (word >> (32 - shift));
}

/* HASH算法，COPY自LINUX内核源代码 */
#define __frag_common_hash(a, b, c) {    \
	c ^= b; c -= rol32(b, 14);        \
	a ^= c; a -= rol32(c, 11);        \
	b ^= a; b -= rol32(a, 25);        \
	c ^= b; c -= rol32(b, 16);        \
	a ^= c; a -= rol32(c, 4);        \
	b ^= a; b -= rol32(a, 14);        \
	c ^= b; c -= rol32(b, 24);        \
}

/* HASH算法，COPY自LINUX内核源代码 */
unsigned int frag_common_hash(unsigned int a, unsigned int b, unsigned int c, unsigned int initval) 
{
	a += JHASH_INITVAL;
	b += JHASH_INITVAL;
	c += initval;

	__frag_common_hash(a, b, c);

	return c;
}

#ifdef __cplusplus
}
#endif

