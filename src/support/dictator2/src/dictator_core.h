#ifndef _DICTATOR2_CORE_H_
#define _DICTATOR2_CORE_H_

#include <pthread.h>
#include "internal_mp.h"
#include "dummy_hash.h"

#define	DICTATOR2_VERSION	"v1.3"
#if(__GNUC__ * 100 + __GNUC_MINOR__ * 10 + __GNUC_PATCHLEVEL__ >= 410)
#define atomic_inc(x) __sync_add_and_fetch((x),1)
#define atomic_dec(x) __sync_sub_and_fetch((x),1)
#define atomic_add(x,y) __sync_add_and_fetch((x),(y))
#define atomic_sub(x,y) __sync_sub_and_fetch((x),(y))
typedef long atomic_t;
#define ATOMIC_INIT(i)  { (i) }
#define atomic_read(x) __sync_add_and_fetch((x),0)
#define atomic_set(x,y) __sync_lock_test_and_set((x),y)
#else 
typedef long atomic_t;
#define atomic_inc(x)	((*(x))++)
#define atomic_dec(x)	((*(x))--)
#define atomic_add(x,y) ((*(x))+=(y))
#define atomic_sub(x,y) ((*(x))-=(y))
#define ATOMIC_INIT(i)  { (i) }
#define atomic_read(x) 	(*(x))
#define atomic_set(x,y)	((*(x))=(y))
#endif 
#include "D_internal/D_kernel_list.h"
#include "D_internal/MESA_hash_v2.h"

const unsigned int	MAX_CHAIN_NUM_SUPPORT=128*3;
const unsigned int	MAX_TRHEAD_NUM_SUPPORT=1024;
const unsigned int	MAX_THREAD_RAWMEM_CNT=1024*4;
const unsigned int	DICTATOR_UNIT_SIZE=32;
const unsigned int	BATCH_DBG_IDX_NUM=MAX_CHAIN_NUM_SUPPORT*256;


#ifndef MAX
#define MAX(a, b)  	(((a) > (b)) ? (a) : (b))
#endif

#ifndef MIN
#define MIN(a, b)  	(((a) < (b)) ? (a) : (b))
#endif

const unsigned int	DICTATOR_MAGIC=0x5210;
#define	MAX_BACKTRACE_DEPTH	32
#define	MALLOC_SELF_DEPTH		3
#define	FREE_SEFL_DEPTH		3

#define	D_MARKER_SIZE	1024
enum CHUNK_STATE
{
	CHUNK_STATE_MALLOC=0,
	CHUNK_STATE_FREE,
	CHUNK_STATE_VIGRIN,
	CHUNK_STATE_REALLOC
};
struct backtrace_info_t
{
	atomic_t ref_cnt;
	atomic_t ref_bytes;
	atomic_t maxsize;
	void** bt_array;
	size_t array_size;
	IMP_t* p_mempool;
};
struct dbg_index_t
{
	unsigned int used_size;
	unsigned int assigned_size;
	struct D_kernel_list_head malloced_in_reach_hook;
	struct backtrace_info_t* p_backtrace;
	void* mem_info;
};
typedef struct mem_info{

#ifdef DICTATOR_DEBUG
	unsigned short magic;
	unsigned short D_id;
	unsigned int blk_num:31;
	unsigned short type:1;	// 0:mmap,  1:DPDK_HUGEPAGE
	struct dbg_index_t* idx;
#else
	unsigned int blk_num;	
	unsigned short D_id;
	unsigned short type; // 0:mmap,  1:DPDK_HUGEPAGE
#endif

	struct mem_info *next;//used only if free
} mem_info_t;
//__attribute__((packed))
typedef struct buffer_container{
	size_t available_size;
	char *buffer;
}buffer_container_t;

typedef struct mem_queue{
	mem_info_t * head;
	mem_info_t * tail;
	atomic_t ele_cnt;
	pthread_mutex_t mutex_tail_lock;
}mem_queue_t;

typedef struct _thread_mem_debugger
{
	atomic_t cached_mem;//dictator managed mem,less than total mem
	atomic_t app_mem;	//application applied mem size,inlucding  not managed mem,less than total_mem
	atomic_t assigned_mem;//dictator assigned to application
	atomic_t inuse_num;
	atomic_t malloc_cnt;
	atomic_t free_cnt;
	atomic_t selfcost_mem;//used by dictator itself
	MESA_hash_tab_v2_t malloc_backtrace_hash;
	MESA_hash_tab_v2_t free_backtrace_hash;
	pthread_mutex_t mutex_malloced_in_reach_list;
	struct D_kernel_list_head malloced_in_reach_list;

	atomic_t pool_unit_cnt;
	struct D_kernel_list_head index_pool;
	pthread_mutex_t mutex_pool_tail;
	unsigned int rawmem_idx;
	void* raw_mem_header[MAX_THREAD_RAWMEM_CNT];
}thread_mem_debugger_t;

typedef struct thread_mem_pool{
	unsigned short D_id;
	pthread_t tid;
	int t_seq;
	int rawmem_idx;
	mem_queue_t block_chain[MAX_CHAIN_NUM_SUPPORT];
	buffer_container_t block_buffer_container;
	void* raw_mem_header[MAX_THREAD_RAWMEM_CNT];
#ifdef	DICTATOR_DEBUG
	thread_mem_debugger_t debugger;
#endif	
}thread_mem_pool_t;

struct dictator_space_t
{
	unsigned int POWER[MAX_CHAIN_NUM_SUPPORT]; 
	unsigned int INIT_THREAD_BLOCK_NUM;
	
	struct dummy_htable_t tid2idx;
	int	tseq2idx[MAX_TRHEAD_NUM_SUPPORT];
	
	thread_mem_pool_t *thread_mem_info[MAX_TRHEAD_NUM_SUPPORT];
	atomic_t used_mem_pool_counter;
	int page_size;
};

inline mem_info_t *get_block(thread_mem_pool_t *thread_info,unsigned int block_num);
inline void restore_block(thread_mem_pool_t* thread_info,mem_info_t *block);

unsigned int calc_block_num(size_t alloc_size);
inline mem_info_t* fill_empty_block(mem_info_t* block,unsigned int blk_num,unsigned short D_id);

thread_mem_pool_t *create_mem_pool(unsigned short D_id);
backtrace_info_t* create_bt_info(void** bt_array,int size);
backtrace_info_t* backtrace_ref_inc(MESA_hash_tab_v2_t* hash,size_t inc_size,thread_mem_pool_t *p_mempool);
struct dbg_index_t* get_dbg_index(thread_mem_debugger_t* debugger);
void restore_dbg_index(thread_mem_debugger_t* debugger,struct dbg_index_t*idx);
thread_mem_pool_t *create_mem_pool(unsigned short D_id);
void init_debugger(thread_mem_debugger_t* debugger,thread_mem_pool_t* p_mp);

void * dictator_debug_thread(void* param);
void D_check_mem(int sd,int is_scheduled);
#define USED_MEM_HEAD_LEN	(sizeof(mem_info_t)-sizeof(struct mem_info *))
#define	D_HEADER(ptr)	((mem_info_t *)((char*)(ptr)-USED_MEM_HEAD_LEN))
#define	D_MEM(ptr)	((char*)(ptr)+USED_MEM_HEAD_LEN)
#define	IS_CHUNK(x)	((x)>(D_SPACE.POWER[MAX_CHAIN_NUM_SUPPORT-1]))

inline unsigned int calc_block_num(size_t alloc_size){
	unsigned int block_num=0;
	if(alloc_size%DICTATOR_UNIT_SIZE==0)
	{
	        block_num = alloc_size/DICTATOR_UNIT_SIZE;
#ifdef  DICTATOR_DEBUG
	        block_num++;
#endif
	}
	else
	{
	        block_num = (alloc_size/DICTATOR_UNIT_SIZE)+1;
	}
	return block_num;
}


#endif

