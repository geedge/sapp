#ifndef _IP_REASSEMBLY_H_
#define _IP_REASSEMBLY_H_

#include "stream_internal.h" 


#define USE_MESA_STREAM_HASH			(1) /* ʹ�û�������ģʽ�µ�HASH�� */	
#if USE_MESA_STREAM_HASH
#include "MESA_htable.h"
#endif

#define IP_FRAG_DEFAULT_BUF_SIZE		(2048) /* Ԥ����Ĭ��IP��Ƭ���黺������С, ͨ��ͳ�Ƶó�, ������IP������С��2KB��ռ90%���� */

#define IP_FRAG_OK					(0x00)	/* ������� */
#define IP_FRAG_INVALID_PACKET			(0x10)	/* ��Ч��Ƭ�����˷�Ƭ�����ٴ���������������ͬһIPQ����һ����Ƭ�� */
#define IP_FRAG_DISCARD				(0x08)	/* ������Ƭ���������ͷ�����IPQ���� */
#define IP_FRAG_IGNORE					(0x04)	/* ������Ƭ�����Ժ�ͬһIPQ���еķ�Ƭ�������ٴ������������IPQ��ֱ����ʱ */

#define IP_FRAG_FIRST_IN              		(0x02)	/* ���յ��˵�һ����Ƭ�� */
#define IP_FRAG_LAST_IN               		(0x01)	/* ���յ������һ����Ƭ�� */


struct addr_list{
	struct layer_addr addr;
	struct addr_list *next;
};


/* һ����Ƭ�� */
struct ip_frags{
	int offset;				/* �˷�Ƭ����һ���ֽ����ԭʼ����ƫ���� */
	int end;            	/* �˷�Ƭ�����һ���ֽ����ԭʼ����ƫ���� */
	struct ip_frags *next;	/* �˷�Ƭ���ڷ�Ƭ�����еĺ�̽ڵ� */
	struct ip_frags *prev;	/* �˷�Ƭ���ڷ�Ƭ�����е�ǰ���ڵ� */
};


/* ��Ƭ������� */
struct frag_ipq{
	int buf_size; 		/* ��IP������ĳ��� */
	short last_in; 		/* ��־λ���յ���һ���������һ���� */
	short attack_flag;  /* ��־λ���Ƿ��⵽���⹥�����ݰ� */
	int tot_len; 		/* ��ǰ�յ���Ƭ�������ƫ���� */
	int meat;			/* ʵ���յ���IP��Ƭ����Ч���ݳ��� */
	unsigned int hash_index; 	/* ����������HASHֵ���Ժ��ظ�ʹ�ã������ٴμ��� */
	int hash_key_size;
	int private_len;	/* ��Э��������صĶ����������� */
	int frags_num;		/* �յ��ķ�Ƭ������ */
	time_t create_time; /* ipq����ʱ�䣬���յ���һ����Ƭ����ʱ�� */
	void *new_iph; 		/* ��������IP��ͷ��ָ�� */
	struct ip_frags *fragments;			/* ��Ƭ������ͷ */
	struct ip_frags *fragments_tail;	/* ��Ƭ������β */
	int frags_len;
#if USE_MESA_STREAM_HASH
	int thread_num;	/* ʹ����HASHʱ, thread_num���ô���, ���ڴ˽ṹ�� */
#else
	struct frag_ipq *hash_prev;  		/* HASH��ͻ������ǰ���ڵ� */
	struct frag_ipq *hash_next;  		/* HASH��ͻ�����ĺ�̽ڵ� */
	struct frag_ipq *lru_prev;  		/* LRU������ǰ���ڵ� */
	struct frag_ipq *lru_next;  		/* LRU�����ĺ�̽ڵ� */
#endif	
	void *hash_key; /* hash key����Э���޹أ��ɹ���ģ������ռ䣬������hash_key_sizeָ�� */
	void *private_info; 	/* ��Э��������صĶ�������������������ռ�, ������private_lenָ�� */
	raw_ipfrag_list_t *ipfrag_list; /* ��ʱ�洢����ԭʼ��Ƭ�� */
};


/* ��Ƭ����Ĺ����ṹ�������Э��汾�޹� */
struct frag_manage{
	int thread_num;					/* �߳�ID */
	unsigned int total_mem;			/* ��ǰռ���ڴ����� */
#if USE_MESA_STREAM_HASH
	MESA_htable_handle frag_hash_table;
#else
	unsigned int hash_table_size;	/* HASH����С */
	int __pad__;
	struct frag_ipq **frag_hash_table;					/* HASH��ͷָ�� */
	unsigned int (*hash_index)(void *hash_key);			/* HASH����ָ�� */
	int (*hash_cmp)(void *hash_key1, void *hash_key2);	/* key�ȽϺ���ָ�� */
	struct frag_ipq *lru_head;	/* lru����ͷ */
	struct frag_ipq *lru_tail;	/* lru����β */
#endif	
	int scratch_frag_cnt;
	int scratch_frag_len;
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
