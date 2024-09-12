#ifndef _IP_REASSEMBLY_H_
#define _IP_REASSEMBLY_H_

#include "stream_internal.h" 


#define USE_MESA_STREAM_HASH			(1) 
#if USE_MESA_STREAM_HASH
#include "MESA_htable.h"
#endif

#define IP_FRAG_DEFAULT_BUF_SIZE		(2048) 

#define IP_FRAG_OK					(0x00)	
#define IP_FRAG_INVALID_PACKET			(0x10)	
#define IP_FRAG_DISCARD				(0x08)	
#define IP_FRAG_IGNORE					(0x04)	

#define IP_FRAG_FIRST_IN              		(0x02)	
#define IP_FRAG_LAST_IN               		(0x01)	


struct addr_list{
	struct layer_addr addr;
	struct addr_list *next;
};


struct ip_frags{
	int offset;				
	int end;            	
	struct ip_frags *next;	
	struct ip_frags *prev;	
};


struct frag_ipq{
	int buf_size; 		
	short last_in; 		
	short attack_flag;  
	int tot_len; 		
	int meat;			
	unsigned int hash_index; 	
	int hash_key_size;
	int private_len;	
	int frags_num;		
	time_t create_time; 
	void *new_iph; 		
	struct ip_frags *fragments;			
	struct ip_frags *fragments_tail;	
	int frags_len;
#if USE_MESA_STREAM_HASH
	int thread_num;	
#else
	struct frag_ipq *hash_prev;  		
	struct frag_ipq *hash_next;  		
	struct frag_ipq *lru_prev;  		
	struct frag_ipq *lru_next;  		
#endif	
	void *hash_key; 
	void *private_info; 	
	raw_ipfrag_list_t *ipfrag_list; 
};


struct frag_manage{
	int thread_num;					
	unsigned int total_mem;			
#if USE_MESA_STREAM_HASH
	MESA_htable_handle frag_hash_table;
#else
	unsigned int hash_table_size;	
	int __pad__;
	struct frag_ipq **frag_hash_table;					
	unsigned int (*hash_index)(void *hash_key);			
	int (*hash_cmp)(void *hash_key1, void *hash_key2);	
	struct frag_ipq *lru_head;	
	struct frag_ipq *lru_tail;	
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
