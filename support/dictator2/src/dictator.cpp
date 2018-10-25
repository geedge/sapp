/*
 * Manage program memory,for high perfomance and exclusive application.
 * The dictator will hoard memory for program to reduce malloc time cost.
 * Version : 2014-12-15
 * Usage:LD_DICTATOR = -Wl,-wrap,malloc -Wl,-wrap,calloc -Wl,-wrap,free -Wl,-wrap,realloc,add LD_DICTATOR as ld parameter.
 * Zheng Chao, zhengchao@iie.ac.cn
 *
 * History:
 *	2010-11-30 first build
 *	2010-12-14 to reduce memory waste,change block list from exponential(e.g.64,128,256,512...)to linearity (e.g. 64,128,192,256...)
 *	2010-12-16 to resolve productor and consumer problem, thread 1 free thread 2's mem block,add block to thread 2's tail,
 *	use mutex to protect the block queues tail.
 *	2010-12-20 fix core_realloc memcpy read out line.
 *	2010-12-29 use gcc buildin atomic operation to proctec chain ele_cnt,use volatile to describe thread stat value
 *	2010-12-30 redesigned mem_info_t struct,reduce mem used from 40 to 8;not suport slice;
 *	2011-01-05 change block assigned strategy,POWER[].
 *	2011-01-28 use <alsa/iatomic.h> as atomic operation
 *	2011-02-14 check block's tid,if from unactivated thread
 *	2011-11-21 strict check block size ,whether it suit chain index in free with assert
 *	2013-12-26 DICTATOR2 first build.
 *	2014-01-17 DICTATOR2 v1.0 released.
 *	2014-06-18 fix realloc memcpy over read ptr bug.
 *	2014-12-02 use mesa_backtrace(student wangpeng@iie.ac.cn) replace glibc backtrace or libunwind backtrace.
 *	2014-12-08 use array replace hash to implement tid2idx and tseq2idx.
 * Notes:
 *	
 *	block(dictator manged) < chunk (system mmap alloced)
 *	
 */

#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>//using memset
#include <malloc.h>
#include <time.h>
#include <new>
#include <pthread.h>
#include <sys/mman.h>
//#define	DPDK_HUGE_PAGE

#ifdef	DPDK_HUGE_PAGE
#include <marsio.h>
#endif

#include "internal_mp.h"
#include "dictator.h"
#include "dictator_core.h"
#include "dummy_hash.h"


#ifdef	DICTATOR_DEBUG
const char* DICTATOR2_VERSION_20170910_DEBUG="DICTATOR2_VERSION_1_3_20170910_DEBUG";
#else
const char* DICTATOR2_VERSION_20170910="DICTATOR2_VERSION_1_3_20170910";
#endif
#define FREE_MEM_HEAD_LEN	(sizeof(mem_info_t))
struct dictator_space_t D_SPACE;
#define	D_THREAD_HASH_SIZE	4*1024
int is_first=0;
const unsigned int LINEAR_1_BOUNDARY=1024;
const unsigned int LINEAR_2_FACTOR=8;

char boundary_marker[D_MARKER_SIZE]={'d'};
#define	PAGE_SIZE	4096
#define	ELF_MIN_ALIGN	PAGE_SIZE
#define	ELF_PAGEALIGN(_v)	(((_v)+ELF_MIN_ALIGN-1)&~(ELF_MIN_ALIGN-1))

inline pid_t gettid(void){
	pid_t ret=(pid_t)pthread_self();
	return ret;
}
mem_info_t* fill_empty_block(mem_info_t* block,unsigned int blk_num,unsigned short D_id){
	block->blk_num=blk_num;
	block->D_id=D_id;
#ifdef DICTATOR_DEBUG
	block->magic=DICTATOR_MAGIC;
	block->idx=NULL;
#endif
	block->next=NULL;
	block->type=0;
	return block;
}
inline int D_hash_key_comp(uchar * key1, uint size1, uchar * key2, uint size2)
{
	assert(size1==sizeof(int)&&size2==sizeof(int));
	if(*(int*)key1==*(int*)key2)
	{
		return 0;	
	}
	else
	{
		return 1;
	}
}
inline unsigned int D_hash_key2index(MESA_hash_tab_v2_t * table, uchar *str, uint size)
{
	assert(size==sizeof(int));
	return (*(unsigned int*)str % table->size);
}
inline static int  tid2idx(pthread_t * array,int size,pthread_t tid)
{
	int i=0;
	for(i=size-1;i>=0;i--)
	{
		if(array[i]==tid)
		{
			return i;
		}
	}
	return -1;
}

inline static thread_mem_pool_t* locate_mp_by_tseq(int t_seq)
{
	long idx=0;
	int ret=0;
	pthread_t tid=0;
	thread_mem_pool_t* p_mempool=NULL;
	idx=D_SPACE.tseq2idx[t_seq];
	if(idx>=0)
	{
		p_mempool=D_SPACE.thread_mem_info[idx];
	}
	if(p_mempool==NULL)
	{
		tid=pthread_self();
		ret=dummy_htable_read(&(D_SPACE.tid2idx), (long)tid,&idx);
		if(ret==1)
		{
			p_mempool=D_SPACE.thread_mem_info[idx];
		}
		if(p_mempool==NULL)
		{
			atomic_inc(&(D_SPACE.used_mem_pool_counter));//here is not thread safe but __sync_add_and_fetch not support in all OS
            idx = atomic_read(&(D_SPACE.used_mem_pool_counter));
			p_mempool=create_mem_pool(idx);
			p_mempool->tid=tid;
#ifdef	DICTATOR_DEBUG
			init_debugger(&(p_mempool->debugger),p_mempool);
#endif
			D_SPACE.thread_mem_info[idx]=p_mempool;
			dummy_htable_add(&(D_SPACE.tid2idx),tid,idx);
			D_SPACE.tseq2idx[t_seq]=idx;
		}
		p_mempool->t_seq=t_seq;	
	}
#ifdef	DICTATOR_DEBUG
	tid=pthread_self();
	assert(p_mempool->t_seq==t_seq);
	assert(tid==p_mempool->tid);
#endif
	return p_mempool;
}
inline static thread_mem_pool_t* locate_mp_by_tid(pthread_t tid)
{
	thread_mem_pool_t* p_mempool=NULL;
	long idx=0;
	int ret=0;
	ret=dummy_htable_read(&(D_SPACE.tid2idx), tid, &idx);
	if(ret==1)
	{
		p_mempool=D_SPACE.thread_mem_info[idx];
	}
	if(p_mempool==NULL)
	{
		atomic_inc(&(D_SPACE.used_mem_pool_counter));
		idx = atomic_read(&(D_SPACE.used_mem_pool_counter));
		p_mempool=create_mem_pool(idx);
		p_mempool->tid=tid;
#ifdef	DICTATOR_DEBUG
		init_debugger(&(p_mempool->debugger),p_mempool);
#endif
		D_SPACE.thread_mem_info[idx]=p_mempool;
		dummy_htable_add(&(D_SPACE.tid2idx), tid, idx);
	}
	return p_mempool;
}
thread_mem_pool_t* init_dictator(pthread_t tid)
{
	unsigned int i=1;
	thread_mem_pool_t* p_mempool=NULL;
	is_first=1;
	D_SPACE.INIT_THREAD_BLOCK_NUM=0;
	assert(getpagesize()==PAGE_SIZE);
	D_SPACE.POWER[0]=1;
	for(i=1;i<MAX_CHAIN_NUM_SUPPORT;i++)
	{
		if((i+1)*DICTATOR_UNIT_SIZE<=LINEAR_1_BOUNDARY)
		{
			D_SPACE.POWER[i]=i+1;
		}
		else
		{
			D_SPACE.POWER[i]=D_SPACE.POWER[i-1]+LINEAR_2_FACTOR;
		}
		D_SPACE.INIT_THREAD_BLOCK_NUM+=D_SPACE.POWER[i];
	}
	D_SPACE.INIT_THREAD_BLOCK_NUM*=2;
	
	//biggest block num
	assert(D_SPACE.POWER[MAX_CHAIN_NUM_SUPPORT-1]<65535);
	memset((void*)D_SPACE.thread_mem_info,0,sizeof(D_SPACE.thread_mem_info));
	atomic_set(&(D_SPACE.used_mem_pool_counter),-1);
	for(i=0;i<MAX_TRHEAD_NUM_SUPPORT;i++)
	{
		D_SPACE.tseq2idx[i]=-1;
	}
	dummy_htable_init(&(D_SPACE.tid2idx));
	p_mempool=locate_mp_by_tid(tid);
#ifdef DICTATOR_DEBUG
	pthread_t	 thread_desc;
	pthread_attr_t attr;
	memset(&thread_desc, 0, sizeof(thread_desc));
	memset(&attr, 0, sizeof(attr));	
	
	if(0 != pthread_attr_init(&(attr))) {
		fprintf(stderr,"pthread_attr_init(): %d %s", errno, strerror(errno));
		return NULL;
	}
	if(0 != pthread_attr_setdetachstate(&(attr), PTHREAD_CREATE_DETACHED)) {
		fprintf(stderr,"pthread_attr_setdetachstate(): %d %s", errno, strerror(errno));
		return NULL;
	}
	if(0 != pthread_create(&(thread_desc), &(attr), (void *(*)(void *))(dictator_debug_thread), NULL)) {
		fprintf(stderr,"pthread_create(): %d %s", errno, strerror(errno));
		pthread_attr_destroy(&(attr));
		return NULL;
	}
	pthread_attr_destroy(&(attr));
	memset(boundary_marker,'d',D_MARKER_SIZE);
#else
	fprintf(stderr,"Using DICTATOR2 memory manager\n");
#endif
	return p_mempool;
}
inline int select_chain(unsigned int block_num){
	assert(block_num<=D_SPACE.POWER[MAX_CHAIN_NUM_SUPPORT-1]);
	if(block_num*DICTATOR_UNIT_SIZE<=LINEAR_1_BOUNDARY)
	{
		return block_num-1;
	}
	else
	{
		if((block_num-LINEAR_1_BOUNDARY/DICTATOR_UNIT_SIZE)%LINEAR_2_FACTOR==0)
			return (block_num-LINEAR_1_BOUNDARY/DICTATOR_UNIT_SIZE)/LINEAR_2_FACTOR+LINEAR_1_BOUNDARY/DICTATOR_UNIT_SIZE-1;
		else
			return (block_num-LINEAR_1_BOUNDARY/DICTATOR_UNIT_SIZE)/LINEAR_2_FACTOR+LINEAR_1_BOUNDARY/DICTATOR_UNIT_SIZE;
	}
	
}
thread_mem_pool_t *create_mem_pool(unsigned short D_id)
{
	unsigned int i=0,assigned_blk_num=0;
	mem_info_t *target_block=NULL;
	thread_mem_pool_t *p=(thread_mem_pool_t *)mmap_alloc(sizeof(thread_mem_pool_t));
	p->block_buffer_container.buffer=(char*)mmap_alloc(DICTATOR_UNIT_SIZE*D_SPACE.INIT_THREAD_BLOCK_NUM);
	if(NULL==p->block_buffer_container.buffer){
		fprintf(stderr,"malloc failed in dictator %s : %d\n",__FILE__,__LINE__);
		assert(0);
	}
	p->raw_mem_header[0]=p->block_buffer_container.buffer;
	p->rawmem_idx=1;
	p->block_buffer_container.available_size=DICTATOR_UNIT_SIZE*D_SPACE.INIT_THREAD_BLOCK_NUM;
	p->D_id=D_id;
	p->t_seq=-1;
	p->tid=0;
	
	//assigned a suitable block for each chain
	for(i=0;i<MAX_CHAIN_NUM_SUPPORT;i++)
	{	
		//get a block
		assigned_blk_num=D_SPACE.POWER[i];
		target_block=(mem_info_t*)p->block_buffer_container.buffer;
		fill_empty_block(target_block,assigned_blk_num ,D_id);
		p->block_buffer_container.buffer+=assigned_blk_num*DICTATOR_UNIT_SIZE;
		p->block_buffer_container.available_size-=assigned_blk_num*DICTATOR_UNIT_SIZE;

		//restore this block
		p->block_chain[i].head=target_block;
		p->block_chain[i].tail=p->block_chain[i].head;
		atomic_set(&(p->block_chain[i].ele_cnt),1);
		pthread_mutex_init(&(p->block_chain[i].mutex_tail_lock), NULL);
	}
	return p;

}




mem_info_t* get_chunk(unsigned short D_id,unsigned int blk_num){
	mem_info_t* block=NULL;
	size_t assigned_size=blk_num*DICTATOR_UNIT_SIZE;
	int is_dpdk_hugepage=0;
#ifdef	DPDK_HUGE_PAGE
	if(marsio_is_hugepage_available()==1)
	{
		block=(mem_info_t*)marsio_hugepage_malloc(assigned_size, D_SPACE.thread_mem_info[D_id]->t_seq);
		is_dpdk_hugepage=1;
	}
	else
	{
		block=(mem_info_t*)mmap(NULL,assigned_size,PROT_WRITE|PROT_READ,MAP_ANONYMOUS|MAP_PRIVATE,-1,0);
	}
#else
	block=(mem_info_t*)mmap(NULL,assigned_size,PROT_WRITE|PROT_READ,MAP_ANONYMOUS|MAP_PRIVATE,-1,0);
#endif


	if(-1==(long)block)
	{
		fprintf(stderr,"mmap/hugepage failed: %s ,at dictator %s : %d\n",strerror(errno),__FILE__,__LINE__);
		_exit(-1);
	}
	fill_empty_block(block,blk_num,D_id);
	block->type=is_dpdk_hugepage;
	if(block->type==0)
	{
		assert((unsigned long)block%PAGE_SIZE==0);
	}
	return block;
}
void* mmap_alloc(size_t size)
{
	mem_info_t*p=NULL;
	unsigned int block_num=0;
	unsigned long assigned_size=0;
	block_num=calc_block_num(size+USED_MEM_HEAD_LEN);
	assigned_size=ELF_PAGEALIGN(block_num*DICTATOR_UNIT_SIZE);
	block_num=assigned_size/DICTATOR_UNIT_SIZE;
	p=get_chunk(0, block_num);
	return D_MEM(p);
}
void mmap_free(void*p)
{
	mem_info_t* block=D_HEADER(p);
	size_t len=block->blk_num*DICTATOR_UNIT_SIZE;
	int ret=0;
#ifdef	DPDK_HUGE_PAGE
	if(block->type==1)
	{
		marsio_hugepage_free(block);
	}
	else
	{
		ret=munmap(block,len);
	}
#else
	ret=munmap(block,len);
#endif
	if(ret!=0)
	{
		fprintf(stderr,"munmap failed: %s ,at dictator %s : %d\n",strerror(errno),__FILE__,__LINE__);
	}
	assert(ret==0);
	return;
}
void* block_alloc(size_t size,IMP_t *imp)
{
	mem_info_t* p=NULL;
	thread_mem_pool_t *p_mempool=(thread_mem_pool_t *)imp;
	unsigned int block_num=calc_block_num(size+USED_MEM_HEAD_LEN);
	assert(!IS_CHUNK(block_num));
	p=get_block(p_mempool,block_num);
#ifdef DICTATOR_DEBUG
	atomic_add(&(p_mempool->debugger.selfcost_mem),p->blk_num*DICTATOR_UNIT_SIZE);
	atomic_sub(&(p_mempool->debugger.cached_mem), p->blk_num*DICTATOR_UNIT_SIZE);
#endif
	return D_MEM(p);
}
void block_free(void*p,IMP_t* imp)
{
	mem_info_t *block=D_HEADER(p);
	thread_mem_pool_t *p_mempool=(thread_mem_pool_t *)imp;
#ifdef DICTATOR_DEBUG
	atomic_sub(&(p_mempool->debugger.selfcost_mem),block->blk_num*DICTATOR_UNIT_SIZE);
	atomic_add(&(p_mempool->debugger.cached_mem), block->blk_num*DICTATOR_UNIT_SIZE);
#endif
	restore_block(p_mempool, block);
	//restore_other_block(p_mempool, block);
	
	return;
}

// own block add to chain head
inline void add_block_to_chain_head(thread_mem_pool_t* thread_info,int chain_idx,mem_info_t* block)
{
	block->next=thread_info->block_chain[chain_idx].head;
	thread_info->block_chain[chain_idx].head=block;
	atomic_inc(&(thread_info->block_chain[chain_idx].ele_cnt));
}
inline void join_block_to_chain_tail(thread_mem_pool_t* thread_info,int chain_idx,mem_info_t* block)
{
	thread_info->block_chain[chain_idx].tail->next=block;
	block->next=NULL;
	thread_info->block_chain[chain_idx].tail=block;
	atomic_inc(&(thread_info->block_chain[chain_idx].ele_cnt));
}
inline void restore_block(thread_mem_pool_t* thread_info,mem_info_t *block)
{
	unsigned int chain_idx=0;
	chain_idx=select_chain(block->blk_num);
	assert(block->blk_num==D_SPACE.POWER[chain_idx]);
	add_block_to_chain_head(thread_info, chain_idx, block);
	return;
}
inline void restore_other_block(thread_mem_pool_t* thread_info,mem_info_t *block)
{
	unsigned int chain_idx=0;
	chain_idx=select_chain(block->blk_num);
	assert(block->blk_num==D_SPACE.POWER[chain_idx]);
	pthread_mutex_lock(&(thread_info->block_chain[chain_idx].mutex_tail_lock));
	join_block_to_chain_tail(thread_info, chain_idx, block);
	pthread_mutex_unlock(&(thread_info->block_chain[chain_idx].mutex_tail_lock));
	
	return;
}
inline mem_info_t *get_block_from_chain(thread_mem_pool_t* thread_info,int chain_idx)
{
	mem_info_t *target=NULL;
#ifdef DICTATOR_DEBUG
	assert(thread_info->block_chain[chain_idx].head!=thread_info->block_chain[chain_idx].tail);
	assert(atomic_read(&(thread_info->block_chain[chain_idx].ele_cnt))>1);
#endif
	target=thread_info->block_chain[chain_idx].head;
	thread_info->block_chain[chain_idx].head=target->next;
	atomic_dec(&(thread_info->block_chain[chain_idx].ele_cnt));
	return target;
}
inline mem_info_t *get_block(thread_mem_pool_t *thread_info,unsigned int block_num)
{
	
	mem_info_t* target_block=NULL,*tmp;
	unsigned int assigned_chain=0;
	unsigned int assigned_size=0;
	assigned_chain=select_chain(block_num);
	assigned_size=D_SPACE.POWER[assigned_chain]*DICTATOR_UNIT_SIZE;
	int i=0;
	assert(assigned_size!=0);
	//block chain is available
	if(thread_info->block_chain[assigned_chain].head!=thread_info->block_chain[assigned_chain].tail&&
											atomic_read(&(thread_info->block_chain[assigned_chain].ele_cnt))>1)
	{
		target_block=get_block_from_chain(thread_info,assigned_chain);
	}
	else
	{
		//block buffer is not enough for this request
		if(thread_info->block_buffer_container.available_size<assigned_size)
		{
			//put left buffer into chain
			assert(thread_info->block_buffer_container.available_size%DICTATOR_UNIT_SIZE==0);
			if(thread_info->block_buffer_container.available_size>0)
			{
				for(i=0;thread_info->block_buffer_container.available_size>0;i++)
				{
					tmp=(mem_info_t *)(thread_info->block_buffer_container.buffer);
					thread_info->block_buffer_container.available_size-=DICTATOR_UNIT_SIZE;
					thread_info->block_buffer_container.buffer+=DICTATOR_UNIT_SIZE;
					fill_empty_block(tmp, 1, thread_info->D_id);
					restore_block(thread_info,tmp);
				}
			}
			//malloc a new buffer
			thread_info->block_buffer_container.buffer=(char *)mmap_alloc(D_SPACE.INIT_THREAD_BLOCK_NUM*DICTATOR_UNIT_SIZE);
			if(NULL==thread_info->block_buffer_container.buffer)
			{
				fprintf(stderr,"malloc failed in dictator %s : %d\n",__FILE__,__LINE__);
				return NULL;
			}
			thread_info->block_buffer_container.available_size=D_SPACE.INIT_THREAD_BLOCK_NUM*DICTATOR_UNIT_SIZE;
			thread_info->raw_mem_header[thread_info->rawmem_idx]=thread_info->block_buffer_container.buffer;
			thread_info->rawmem_idx++;
#ifdef	DICTATOR_DEBUG
			atomic_add(&(thread_info->debugger.cached_mem),D_SPACE.INIT_THREAD_BLOCK_NUM*DICTATOR_UNIT_SIZE);
#endif
		}
		//cut a block from buffer
		target_block=(mem_info_t*)thread_info->block_buffer_container.buffer;
		fill_empty_block(target_block, D_SPACE.POWER[assigned_chain],thread_info->D_id);
		thread_info->block_buffer_container.buffer+=assigned_size;
		thread_info->block_buffer_container.available_size-=assigned_size;	
	}
	return target_block;
	
	
}

void *core_alloc(thread_mem_pool_t *p_mempool,size_t size)
{
	unsigned int block_num=0;
	unsigned long assigned_size=0;
	mem_info_t *target_mem=NULL;
	if(0==size)
	{
		return NULL;
	}
	block_num=calc_block_num(size+USED_MEM_HEAD_LEN);
	if(block_num>D_SPACE.POWER[MAX_CHAIN_NUM_SUPPORT-1])
	{
		assigned_size=ELF_PAGEALIGN(block_num*DICTATOR_UNIT_SIZE);
		block_num=assigned_size/DICTATOR_UNIT_SIZE;
		//malloc with mmap
		target_mem=get_chunk(p_mempool->D_id, block_num);
	}
	else
	{
		target_mem=get_block(p_mempool,block_num);
	}
#ifdef DICTATOR_DEBUG
	backtrace_info_t *caller_bt;
	struct dbg_index_t* dbg_idx=NULL;
	assigned_size=target_mem->blk_num*DICTATOR_UNIT_SIZE;
	dbg_idx=get_dbg_index(&(p_mempool->debugger));
	target_mem->idx=dbg_idx;
	dbg_idx->mem_info=(void*)target_mem;


	//use by thread self and debug thread's threadsafe callback, no need to protect with mutex;
	caller_bt=backtrace_ref_inc(&((p_mempool->debugger.malloc_backtrace_hash)),size,p_mempool);

	
	target_mem->idx->p_backtrace=caller_bt;
	target_mem->idx->used_size=size;
	target_mem->idx->assigned_size=assigned_size;
	
	pthread_mutex_lock(&(p_mempool->debugger.mutex_malloced_in_reach_list));
	D_kernel_list_add_tail(&(p_mempool->debugger.malloced_in_reach_list),&(target_mem->idx->malloced_in_reach_hook));
	pthread_mutex_unlock(&(p_mempool->debugger.mutex_malloced_in_reach_list));

	int boundary_len=assigned_size-size-USED_MEM_HEAD_LEN;
	memset(D_MEM(target_mem)+target_mem->idx->used_size,'d',boundary_len);
	atomic_add(&(p_mempool->debugger.app_mem),size);
	atomic_add(&(p_mempool->debugger.assigned_mem),assigned_size);
	atomic_inc(&(p_mempool->debugger.inuse_num));
	atomic_inc(&(p_mempool->debugger.malloc_cnt));
	if(IS_CHUNK(target_mem->blk_num))
	{
		//no need do free_backtrace_hash ,index for double free check;
	}
	else
	{
		atomic_sub(&(p_mempool->debugger.cached_mem), target_mem->blk_num*DICTATOR_UNIT_SIZE);
	}
#endif
	return D_MEM(target_mem);
}
void core_free(unsigned short caller_Did,void *p)
{
	mem_info_t *block=D_HEADER(p);
	thread_mem_pool_t* p_mempool=D_SPACE.thread_mem_info[block->D_id];
#ifdef DICTATOR_DEBUG
	thread_mem_pool_t* caller_mp=D_SPACE.thread_mem_info[caller_Did];
	backtrace_info_t *caller_bt;
	assert(block->magic==DICTATOR_MAGIC);
	const char* user_boundary=(char*)block+block->idx->used_size+USED_MEM_HEAD_LEN;
	int boundary_len=0;
	unsigned int assigned_size=block->blk_num*DICTATOR_UNIT_SIZE;
	assert(block->idx->assigned_size==assigned_size);
	if(!IS_CHUNK(block->blk_num))//not a chunk
	{
		atomic_add(&(p_mempool->debugger.cached_mem),assigned_size);
	}
	pthread_mutex_lock(&(p_mempool->debugger.mutex_malloced_in_reach_list));
	D_kernel_list_delete(&(p_mempool->debugger.malloced_in_reach_list),&(block->idx->malloced_in_reach_hook));
	pthread_mutex_unlock(&(p_mempool->debugger.mutex_malloced_in_reach_list));
	
	atomic_sub(&(p_mempool->debugger.app_mem),block->idx->used_size);
	atomic_sub(&(p_mempool->debugger.assigned_mem),assigned_size);
	atomic_dec(&(block->idx->p_backtrace->ref_cnt));
	atomic_sub(&(block->idx->p_backtrace->ref_bytes),block->idx->used_size);
	atomic_dec(&(p_mempool->debugger.inuse_num));
	atomic_inc(&(p_mempool->debugger.free_cnt));
	caller_bt=backtrace_ref_inc(&(caller_mp->debugger.free_backtrace_hash),assigned_size,caller_mp);
	block->idx->p_backtrace=caller_bt;

	boundary_len=MIN(assigned_size-block->idx->used_size-USED_MEM_HEAD_LEN,D_MARKER_SIZE);
	assert(0==memcmp(user_boundary,boundary_marker,boundary_len));
	restore_dbg_index(&(p_mempool->debugger), block->idx);
	block->idx=NULL;	
#endif
	if(IS_CHUNK(block->blk_num))
	{
		//a chunk
		mmap_free(D_MEM(block));
	}
	else
	{
		if(block->D_id==caller_Did)
		{
			restore_block(p_mempool, block);

		}
		else
		{
			restore_other_block(p_mempool, block);
		}
	}

}
void *core_realloc(unsigned short caller_Did,void *ptr, size_t size)
{
	mem_info_t *block=D_HEADER(ptr);
	mem_info_t *new_block=NULL;
	void* new_mem=NULL;
	size_t old_size=0;
#ifdef DICTATOR_DEBUG
	size_t new_size=0;
	thread_mem_pool_t* orginal_mempool=D_SPACE.thread_mem_info[block->D_id];
	struct dbg_index_t* tmp_idx=NULL;
	assert(block->magic==DICTATOR_MAGIC);
#endif
	old_size=(block->blk_num*DICTATOR_UNIT_SIZE)-USED_MEM_HEAD_LEN;

	if(IS_CHUNK(block->blk_num))
	{		
#ifdef DICTATOR_DEBUG
		size_t orginal_size=0;
		orginal_size=block->blk_num*DICTATOR_UNIT_SIZE;
		atomic_sub(&(block->idx->p_backtrace->ref_bytes),block->idx->used_size);
		pthread_mutex_lock(&(orginal_mempool->debugger.mutex_malloced_in_reach_list));
		D_kernel_list_delete(&(orginal_mempool->debugger.malloced_in_reach_list),&(block->idx->malloced_in_reach_hook));
		pthread_mutex_unlock(&(orginal_mempool->debugger.mutex_malloced_in_reach_list));
		atomic_sub(&(orginal_mempool->debugger.app_mem),block->idx->used_size);
		atomic_sub(&(orginal_mempool->debugger.assigned_mem),orginal_size);
		tmp_idx=block->idx;
#endif
		if(old_size>=size)
		{
			new_block=block;
		}
		else
		{			
			new_block=D_HEADER(mmap_alloc(size));
			memcpy(D_MEM(new_block),D_MEM(block),old_size);
			mmap_free(D_MEM(block));
		}
		new_mem=D_MEM(new_block);
#ifdef DICTATOR_DEBUG
		new_size=new_block->blk_num*DICTATOR_UNIT_SIZE;
		new_block->idx=tmp_idx;
		new_block->idx->used_size=size;
		new_block->idx->assigned_size=new_size;
		new_block->idx->mem_info=new_block;
		atomic_add(&(new_block->idx->p_backtrace->ref_bytes),size);
		if(atomic_read(&(new_block->idx->p_backtrace->maxsize))<(signed long)size)
		{
			atomic_set(&(new_block->idx->p_backtrace->maxsize),(signed long)size);
		}
		pthread_mutex_lock(&(orginal_mempool->debugger.mutex_malloced_in_reach_list));
		D_kernel_list_add_tail(&(orginal_mempool->debugger.malloced_in_reach_list),&(new_block->idx->malloced_in_reach_hook));
		pthread_mutex_unlock(&(orginal_mempool->debugger.mutex_malloced_in_reach_list));

		memset((char*)new_mem+size,'d',new_size-size-USED_MEM_HEAD_LEN);
		atomic_add(&(orginal_mempool->debugger.app_mem),size);
		atomic_add(&(orginal_mempool->debugger.assigned_mem),new_size);		
#endif
		block=NULL;
	}
	else
	{
		if(old_size>=size)
		{
			new_mem=ptr;
#ifdef	DICTATOR_DEBUG
			atomic_sub(&(orginal_mempool->debugger.app_mem),block->idx->used_size-size);	
			atomic_sub(&(block->idx->p_backtrace->ref_bytes),block->idx->used_size-size);
			block->idx->used_size=size;
#endif
		}
		else
		{
			new_mem=core_alloc(D_SPACE.thread_mem_info[caller_Did],size);
			new_block=D_HEADER(new_mem);
			memcpy((char*)new_mem,
					(char*)ptr,
					old_size);
			core_free(caller_Did,ptr);
		}
	}
	return new_mem;
}

void *__wrap_malloc(size_t size)
{
	thread_mem_pool_t* p_mempool=NULL;
	pthread_t tid=pthread_self();
	if(is_first==0)
	{
		p_mempool=init_dictator(tid);
	}
	else
	{
		p_mempool=locate_mp_by_tid(tid);
	}
	return core_alloc(p_mempool,size);

}

//If ptr is NULL, no operation is performed.
void __wrap_free(void *p)
{
	thread_mem_pool_t* p_mempool=NULL;
	if(p==NULL)
		return;
	pthread_t tid=pthread_self();
	p_mempool=locate_mp_by_tid(tid);
	core_free(p_mempool->D_id,p);
	return;
}

#if 0// close by lijia
void* operator new(size_t size)
{
	if(size==0)
	{
		size=1;
	}
	return __wrap_malloc(size);
}
void* operator new(size_t size,const std::nothrow_t &nothrow_const)
{
	if(size==0)
	{
		size=1;
	}
	return __wrap_malloc(size);
}
void operator delete(void*p)
{
	 __wrap_free(p);
}
#endif

//The contents will be unchanged to the minimum of the old and new sizes;
//If ptr is NULL, the call is equivalent to malloc(size); if size is equal to zero, the call is equivalent to free(ptr).  
//Unless ptr is NULL, it must have been returned by an earlier call to malloc(), calloc() or realloc().
void *__wrap_realloc(void *ptr, size_t size)
{
	pthread_t tid=pthread_self();
	thread_mem_pool_t* p_mempool=NULL;	
	if(is_first==0)
	{
		p_mempool=init_dictator(tid);
	}
	else
	{
		p_mempool=locate_mp_by_tid(tid);
	}
	if(size==0&&ptr!=NULL)
	{
		core_free(p_mempool->D_id,ptr);
		return NULL;
	}
	if(ptr==NULL)
	{
		return core_alloc(p_mempool,size);
	}
	return core_realloc(p_mempool->D_id,ptr,size);
}
/* Maybe conflict with DPDK 
void *malloc(size_t size)
{
	return __wrap_malloc(size);
}
void *realloc(void *ptr, size_t size)
{
	return __wrap_realloc(ptr, size);
}
void *calloc(size_t nmemb, size_t size)
{
	return __wrap_calloc(nmemb, size);
}
void free(void *p)
{
	return __wrap_free(p);
}*/
void *__wrap_calloc(size_t nmemb, size_t size)
{
	thread_mem_pool_t* p_mempool=NULL;
	void* p=NULL;
	pthread_t tid=pthread_self();
	if(is_first==0)
	{
		p_mempool=init_dictator(tid);
	}
	else
	{
		p_mempool=locate_mp_by_tid(tid);
	}
	p=core_alloc(p_mempool,nmemb*size);
	if(p!=NULL)
	{
		memset(p,0,nmemb*size);
	}
	return p;
}
void *__dictator_malloc(int t_seq,size_t size)
{
	thread_mem_pool_t* p_mempool=NULL;
	pthread_t tid=0;
	if(is_first==0)
	{
		tid=pthread_self();
		p_mempool=init_dictator(tid);
	}
	else
	{
		p_mempool=locate_mp_by_tseq(t_seq);
	}
	return core_alloc(p_mempool,size);
}
void __dictator_free(int t_seq,void*p)
{
	unsigned short this_D_id=0;
	if(p==NULL)
	{
		return;
	}
	thread_mem_pool_t* p_mempool=NULL;
	p_mempool=locate_mp_by_tseq(t_seq);
	this_D_id=p_mempool->D_id;
	core_free(this_D_id,p);
	return;
}
void *__dictator_realloc(int t_seq,void*ptr,size_t size)
{
	thread_mem_pool_t* p_mempool=NULL;
	pthread_t tid=0;
	if(is_first==0)
	{
		tid=pthread_self();
		p_mempool=init_dictator(tid);
	}
	else
	{
		p_mempool=locate_mp_by_tseq(t_seq);
	}
	if(size==0&&ptr!=NULL){
		core_free(p_mempool->D_id,ptr);
		return NULL;
	}
	if(ptr==NULL)
	{
		return core_alloc(p_mempool,size);
	}
	return core_realloc(p_mempool->D_id,ptr,size);
}
void *__dictator_calloc(int t_seq,size_t nmemb, size_t size)
{
	thread_mem_pool_t* p_mempool=NULL;
	pthread_t tid=0;
	if(is_first==0)
	{
		tid=pthread_self();
		p_mempool=init_dictator(tid);
	}
	else
	{
		p_mempool=locate_mp_by_tseq(t_seq);
	}
	return core_alloc(p_mempool,nmemb*size);
}

