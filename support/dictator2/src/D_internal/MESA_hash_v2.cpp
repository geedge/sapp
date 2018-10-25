#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include "MESA_hash_v2.h"
#include "MESA_list_v2.h"
#include "list_common.h"
#include "../dictator.h"

#if MESA_HASH_DEBUG
static int *hash_slot_list_num;     /* 用于记录每个slot挂接链表节点数量 */
static int max_slot_list_num = 0;   /* 每个slot最大冲突数 */
#endif
#ifndef MAX
#define MAX(a, b)       (((a) > (b)) ? (a) : (b))
#endif

#ifndef MIN
#define MIN(a, b)       (((a) < (b)) ? (a) : (b))
#endif
/*
 * hash implementation, xh, 2001-07-26
 */
 
/*Developer Notice:
    in hash_add function,hash table MALLOC memory for keys and  RECORD data pointer,
    which means need NOT malloc memory for keys before call hash_add. zhengchao

    2013-05, LiJia, add thread safe implement.
*/


/*
   尽可能减少锁冲突，每N个Hash-slot共享一个互斥锁,
   (HASH_Index % HASH_TABLE_MUTEX_NUM)的值相同的item共享一个mutex.
*/
#define HASH_TABLE_MUTEX_NUM		(256)        


static HASH_INLINE int D_INTERNAL___MESA_hash_mutex_lock(MESA_hash_tab_v2_t * table, uint index)
{   
    if(table->is_thread_safe){
        return pthread_mutex_lock(&table->htable_mutex[index%HASH_TABLE_MUTEX_NUM]);
    }
    return 0;
}

static HASH_INLINE int D_INTERNAL___MESA_hash_mutex_unlock(MESA_hash_tab_v2_t * table,uint index)
{
    if(table->is_thread_safe){
        return pthread_mutex_unlock(&table->htable_mutex[index%HASH_TABLE_MUTEX_NUM]);
    }
    return 0;
}

static int D_INTERNAL___MESA_hash_time_list_insert(MESA_hash_tab_v2_t *table, 
                                       hash_elem_v2_t *hash_elem, uint index)
{
    int ret = 0;
    MESA_queue_head_v2_t *list_head;

    if(table->is_thread_safe){
        list_head = &table->hlist_head[index%HASH_TABLE_MUTEX_NUM];
    }else{
        list_head = &table->hlist_head[0];
    }

    D_INTERNAL_MESA_q_join_tail_v2(list_head, &hash_elem->list_node);

    return ret;
}

static HASH_INLINE void D_INTERNAL___MESA_hash_time_list_delete(MESA_hash_tab_v2_t *table,
                                             hash_elem_v2_t *hash_elem, uint index)
{
    MESA_queue_head_v2_t *list_head;

    if(table->is_thread_safe){
        list_head = &table->hlist_head[index%HASH_TABLE_MUTEX_NUM];
    }else{
        list_head = &table->hlist_head[0];
    }
    D_INTERNAL_MESA_q_leave_list_v2(list_head, &hash_elem->list_node);

    return;
}

static HASH_INLINE int D_INTERNAL___MESA_hash_time_list_lru(MESA_hash_tab_v2_t *table, 
                                    hash_elem_v2_t *hash_elem, uint index)
{
    int ret = 0;
    MESA_queue_head_v2_t *list_head;

    if(table->is_thread_safe){
        list_head = &table->hlist_head[index%HASH_TABLE_MUTEX_NUM];
    }else{
        list_head = &table->hlist_head[0];
    }

    D_INTERNAL_MESA_q_move_tail_v2(list_head, &hash_elem->list_node);
    
    return ret;
}


/* 
    search HASH-table whether has duplicate key. 
*/
static HASH_INLINE hash_elem_v2_t *D_INTERNAL___MESA_hash_key_search(MESA_hash_tab_v2_t * table, 
                                    uchar * key, uint size, uint index)
{
	hash_elem_v2_t * ptr;
	for(ptr = table->elems[index]; NULL != ptr; ptr = ptr->next) {
	    if(!table->key_comp(ptr->key, ptr->size, key, size))
		    break;
    }

    return ptr;
}

static HASH_INLINE void D_INTERNAL___MESA_hash_list_insert(MESA_hash_tab_v2_t * table, 
                                         hash_elem_v2_t * ptr, uint index)
{
	ptr->prev = NULL;
	ptr->next = table->elems[index];
	if(NULL != table->elems[index]){ 
	    table->elems[index]->prev = ptr;
	}    
	table->elems[index] = ptr;
	
	table->elem_count++;
}

static HASH_INLINE void D_INTERNAL___MESA_hash_list_delete(MESA_hash_tab_v2_t * table, 
                                         hash_elem_v2_t * ptr, uint index)
{
	if(NULL != ptr->prev){ 
	    ptr->prev->next = ptr->next;
	}else{
	    table->elems[index] = ptr->next;
	}
	
	if(NULL != ptr->next){
	    ptr->next->prev = ptr->prev;
	}
	
	table->elem_count--;
}

static HASH_INLINE hash_elem_v2_t *D_INTERNAL___MESA_hash_alloc_resource(
                         uchar * key, uint size, void * data, uint index
                         ,IMP_t*p_mempool)
{
    hash_elem_v2_t *ptr = NULL;
	if(NULL == (ptr = (hash_elem_v2_t*)block_alloc(sizeof(hash_elem_v2_t),p_mempool))){
	    goto err_1;
	}
	if(NULL == (ptr->key = (unsigned char*)block_alloc(size,p_mempool))) {
		goto err_2;
	}
	memcpy(ptr->key, key, size);
	ptr->size = size;
	ptr->data = data; /* lijia comment, data指向的内存是调用者申请的 */
	ptr->list_node.nextele = NULL;
	ptr->list_node.preele = NULL;
	ptr->list_node.quiddity = (void *)ptr;
	ptr->op_time = HASH_TIME_NOW();
	ptr->hash_index = index;
	return ptr;

err_2:
    block_free(ptr,p_mempool);
err_1:
    return NULL;
}


static HASH_INLINE void D_INTERNAL___MESA_hash_free_resource(MESA_hash_tab_v2_t * table, 
                                hash_elem_v2_t *ptr, void (* func)(void *))
{
	IMP_t *p_mempool=table->p_mempool;
	if(NULL != func){
	    func(ptr->data);
	}else if(NULL != table->free){
	    table->free(ptr->data);
    }
	block_free(ptr->key,p_mempool);
	block_free(ptr,p_mempool);
}


static HASH_INLINE void D_INTERNAL___MESA_hash_del_node(MESA_hash_tab_v2_t * table, 
                hash_elem_v2_t * ptr, uint index, void (* func)(void *))
{
    D_INTERNAL___MESA_hash_list_delete(table, ptr, index);
	D_INTERNAL___MESA_hash_time_list_delete(table, ptr, index);
	D_INTERNAL___MESA_hash_free_resource(table, ptr, func);
}

/*
    kick out a oldest node from HASH-table if elements number exceed threshold, 
    or the node's operate time expired.
*/
static void D_INTERNAL___MESA_hash_eliminate(MESA_hash_tab_v2_t *table, uint index)
{
    MESA_list_index_v2_t *list_head, *oldest_node;
    hash_elem_v2_t *hash_elem; 
    int do_eliminate = 0;
    if(table->is_thread_safe){
        list_head = &table->hlist_head[index%HASH_TABLE_MUTEX_NUM];
    }else{
        list_head = &table->hlist_head[0];
    }

    oldest_node = D_INTERNAL_MESA_q_read_head_v2(list_head);
    if(oldest_node){
        hash_elem = (hash_elem_v2_t *)oldest_node->quiddity;
        if((table->max_elem_num != 0)
           && (table->elem_count > table->max_elem_num)){ /* too many elements */
            do_eliminate |= 0x01;
        }else if((table->expire_time != 0)
                &&(hash_elem->op_time + table->expire_time < HASH_TIME_NOW())){ /* time expired */
                do_eliminate |= 0x10;
        }
        if(do_eliminate != 0){ 
            if(table->expire){
                table->expire(hash_elem->data);
            }
            D_INTERNAL___MESA_hash_del_node(table ,hash_elem, hash_elem->hash_index, NULL);
            //printf("eliminate a oldest element!\n");
        }
    }
}

/*
 * name: D_INTERNAL___default_hash_key2index
 * functionality: computes index from key, default key2index implementation
 * 	if previous hash_create() call did not provide such a function;
 * params:
 * 	table: with which table are you dealing, we want this param be present
 * 	    because we may need size of table to compute the key;
 * 	key: what is the label;
 * 	size: how long is the label;
 * returns:
 * 	index in given table for given key, never fails;
 */
#if 0 
static uint D_INTERNAL___default_hash_key2index(MESA_hash_tab_v2_t * table, uchar * key, uint size)
{
	uchar * c;
	uint h, g;

	for (c = key, h = 0; c - key < size; c ++) {
		h = (h << 2) + c[0];
		if(0 != (g = (h & 0xf0000000))) {
			h = h ^ (g >> 24);
			h = h ^ g;
		}
	}
	return h % table->size;
}
#else
/* BKDR Hash Function */
static uint D_INTERNAL___default_hash_key2index(MESA_hash_tab_v2_t * table, uchar *str, uint size)
{
    uint i;
	uint seed = 131; // 31 131 1313 13131 131313 etc..
	uint hash = 0;
 	uint cmp_size=MIN(size,96);
	for(i = 0; i < cmp_size; i++){
		if((i&0x7)<3)
		{
			hash = hash * seed + (*str++);
		}
	}
 
	return (hash % table->size);
}
#endif

/*
 * name: D_INTERNAL___default_hash_key_comp
 * functionality: compares two key;
 * params:
 * 	key1, key2: what are the labels;
 * 	size1, size2: how long are them;
 * returns:
 * 	0, if two keys are identical; (just a simple memcmp() );
 * 	1, no.
 */
static int D_INTERNAL___default_hash_key_comp(uchar * key1, uint size1, uchar * key2, uint size2)
{
	if(size1 != size2) return 1;
	return memcmp(key1, key2, size1);
}

/* 检验是否2的N次方 */
static HASH_INLINE int D_INTERNAL_number_is_2N(uint n)
{
#if 0
	uint s;
	for(s = n; s != 0; ) {
		if(0x01 != s && 0x01 == (0x01 & s)) return 0;
		s = s >> 1;
	}
#else
    if(n & (n-1)){
        return 0;
    }    
#endif

	return 1;
}

/*
 * name: hash_create
 *  functionality: allocats memory for hash slots, and fill in hash structure;
 * param:
 * 	table: caller allocated hash table structure, gets filled in;
 *	is_thread_safe:1:create thread safe hashtable; 0:create hashtable without thread safe insurance; 
 * 	size: how big do you want the table to be, must be 2^N;
 *  max_elem_num: the maximum elements of the HASH-table,0 means infinite;
 * 	key_comp: hash key compare function, use default function if NULL;
 *  key2index: hash key->index computing function, use default function if NULL;
 *  data_free: release resources function, only free attached data pointer if NULL;
 *  data_expire: if expire_time > 0, call this function when a element expire, can be NULL;
 *  eliminate_type: the algorithm of elimanate a expired element, 0:FIFO; 1:LRU.
 *  expire_time: the element expire time in second, 0 means infinite.
 * returns:
 * 	0, success;
 * 	-1, memory failure;
 * 	-2, parameter not acceptable;
 */
int D_INTERNAL_MESA_hash_create_v2(MESA_hash_tab_v2_t * table, uint is_thread_safe,
                              uint size, uint max_elem_num,
	                          key_comp_t * key_comp, 
	                          key2index_t * key2index,
	                          void (* data_free)(void *),
	                          void (* data_expire)(void *),
	                          int eliminate_type,
							  int expire_time,
							  IMP_t* p_mempool)
{
	int i=0,j, ret = 0;

    if(D_INTERNAL_number_is_2N(size) == 0){
        return -2;
    }

	table->elems = (hash_elem_v2_t**)mmap_alloc(sizeof(hash_elem_v2_t *) * size);
	if(NULL == table->elems)
		return -1;
	memset(table->elems, 0, sizeof(hash_elem_v2_t *) * size);
	table->size = size;
	if(NULL == key_comp) table->key_comp = D_INTERNAL___default_hash_key_comp;
	else table->key_comp = key_comp;
	if(NULL == key2index) table->key2index = D_INTERNAL___default_hash_key2index;
	else table->key2index = key2index;
	table->expire = data_expire;
	//if(NULL == data_free) return -1; /* 2013-05-06 modify, can be NULL */
	table->free = data_free;
	table->elem_count = 0;
	table->max_elem_num = max_elem_num;
	//table->threshold_lo = 0;
	//table->threshold_hi = size;
	table->eliminate_type = eliminate_type;
	table->expire_time = expire_time;
	table->is_thread_safe = is_thread_safe;
	table->p_mempool=p_mempool;
    if(table->is_thread_safe){
        table->htable_mutex = (pthread_mutex_t *)mmap_alloc(sizeof(pthread_mutex_t) * HASH_TABLE_MUTEX_NUM);
        if(NULL == table->htable_mutex){
            ret = -1;
            goto err_1;
        }
        for(i = 0; i < HASH_TABLE_MUTEX_NUM; i++){
            if(pthread_mutex_init(&table->htable_mutex[i], NULL)!=0){
                ret = -1;
                goto err_2;
            }   
        }   
        table->hlist_head = (MESA_list_index_v2_t *)mmap_alloc(sizeof(MESA_list_index_v2_t) * HASH_TABLE_MUTEX_NUM);
        if(NULL == table->hlist_head){
            ret = -1;
            goto err_2;
        }        
        for(i=0;i<HASH_TABLE_MUTEX_NUM;i++){
            D_INTERNAL_MESA_list_init_v2(&table->hlist_head[i]);
        }
    }else{
        table->hlist_head = (MESA_list_index_v2_t *)mmap_alloc(sizeof(MESA_list_index_v2_t));
        if(NULL == table->hlist_head){
            ret = -1;
            goto err_2;
        }
        D_INTERNAL_MESA_list_init_v2(&table->hlist_head[0]);
    }

	return 0;

err_2:
    for(j = 0; j < i; j++){
        pthread_mutex_destroy(&table->htable_mutex[j]);
    }
    mmap_free(table->htable_mutex);
err_1:
    mmap_free(table->elems);
    return ret;
}

/*
 * frees table->elems and chains attached to each element of it.
 * always returns 0.
 */
int D_INTERNAL_MESA_hash_destroy_v2(MESA_hash_tab_v2_t * table, void (* func)(void *))
{
	int i;
	hash_elem_v2_t * cur;
	IMP_t* p_mempool=table->p_mempool;
	for(i = 0; i < (int)table->size; i ++) {
		while(NULL != table->elems[i]) {
			cur = table->elems[i];
			if(NULL != func) func(cur->data);
			else if(NULL != table->free) table->free(cur->data);
			table->elems[i] = (table->elems[i])->next;
			block_free(cur->key,p_mempool);
			block_free(cur,p_mempool);
		}
	}
    if(table->is_thread_safe){
        for(i=0;i<HASH_TABLE_MUTEX_NUM;i++)
            pthread_mutex_destroy(&table->htable_mutex[i]);
        mmap_free(table->htable_mutex);    
    }
	mmap_free(table->hlist_head);
	mmap_free(table->elems);
	table->elems = NULL;
	table->size = 0;

	return 0;
}

/*
 * adds data identified by key to table.
 * table->elems always points to the newest added element.
 * no two elements should have a same key, although them may have a same index.
 * returns:
 * -1, if duplicate is found;
 * -2, if memory fails;
 *  0, success.
 */
int D_INTERNAL_MESA_hash_add_v2(MESA_hash_tab_v2_t * table, uchar * key, uint size,
											void * data)
{
    uint index;
    hash_elem_v2_t * ptr;
    int ret = 0;
	IMP_t *p_mempool=table->p_mempool;
    index = table->key2index(table, key, size);
	
    D_INTERNAL___MESA_hash_mutex_lock(table,index);
	if(D_INTERNAL___MESA_hash_key_search(table,key,size,index)){ /* already exist */
	    ret = -1;
		goto err;
	}
    ptr = D_INTERNAL___MESA_hash_alloc_resource(key, size, data, index,p_mempool);
    if(NULL == ptr){ 
        ret = -2;
        goto err;
    }
    D_INTERNAL___MESA_hash_list_insert(table, ptr, index);
    D_INTERNAL___MESA_hash_time_list_insert(table, ptr, index);

    D_INTERNAL___MESA_hash_eliminate(table,index);
    
    D_INTERNAL___MESA_hash_mutex_unlock(table,index);

#if MESA_HASH_DEBUG
    hash_slot_list_num[index]++;
    if(max_slot_list_num < hash_slot_list_num[index]){
        max_slot_list_num = hash_slot_list_num[index];
        printf("Hash table max list num:%d\n", max_slot_list_num);
    }
#endif

	return 0;

err:
    D_INTERNAL___MESA_hash_mutex_unlock(table,index);
    return ret;
}



/*
 * name: hash_del
 * functionality: deletes item from table.
 * param:
 * 	table: from which table do you want to delete;
 * 	key  : what is the label;
 * 	size : how long is the label;
 * 	func : callback function to clean up data attached to hash items,
 	       if this pointer is NULL will call "data_free" in MESA_hash_create(),
 * returns:
 * 	0, success;
 * 	-1, no such thing;
 */
int D_INTERNAL_MESA_hash_del_v2(MESA_hash_tab_v2_t * table, uchar * key, uint size,
                         void (* func)(void *))
{
	uint index;
	hash_elem_v2_t * ptr;
	int ret = 0;
	index = table->key2index(table, key, size);
	
    D_INTERNAL___MESA_hash_mutex_lock(table,index);
    ptr = D_INTERNAL___MESA_hash_key_search(table,key,size,index);
	if(NULL == ptr){
        ret = -1;
	    goto err;	/* success, maybe? why? */
	}

    D_INTERNAL___MESA_hash_del_node(table ,ptr, index, func);

    //D_INTERNAL___MESA_hash_eliminate(table,index);
    
	D_INTERNAL___MESA_hash_mutex_unlock(table,index);

	return ret;

err:
    D_INTERNAL___MESA_hash_mutex_unlock(table,index);
    return ret;
}

/*
 * name: hash_sel
 * functionality: selects item from table;
 * param:
 * 	table: from which table do you want to select;
 * 	key: what is the label;
 * 	size: how long is the label;
 *
 * return:
 *  not NULL :pointer to attached data;
 *  NULL 	 :not found(thus be careful if you are attaching NULL data on purpose).
 */
void *D_INTERNAL_MESA_hash_sel_v2(MESA_hash_tab_v2_t * table, uchar * key, uint size)
{
	uint index;
	hash_elem_v2_t * ptr;
	void *ret;
	index = table->key2index(table, key, size);
    D_INTERNAL___MESA_hash_mutex_lock(table,index);
    D_INTERNAL___MESA_hash_eliminate(table,index); /* 2013-09-12 LiJia modify, 先淘汰再查找,否则会将查到的结果淘汰而又返回给了调用者 */
    ptr = D_INTERNAL___MESA_hash_key_search(table,key,size,index);
    if(NULL != ptr){
        ret = ptr->data;
        if(HASH_ELIMINATE_ALGO_LRU==table->eliminate_type){
            ptr->op_time = HASH_TIME_NOW();
            D_INTERNAL___MESA_hash_time_list_lru(table, ptr, index);
        }
    }else{
	    ret = NULL;
    }
    
    D_INTERNAL___MESA_hash_mutex_unlock(table,index);
	
    return ret;
}

/*
 * name: hash_sel
 * functionality: selects item from table;
 * in param:
 * 	table: from which table do you want to select;
 * 	key  : what is the label;
 * 	size : how long is the label;
 *  cb   : call this function when found the attached data;
 *  arg  : the argument of "cb" function.
 * out param:
 *  cb_ret: the return value of the function "cb".
 * return:
 *  not NULL :pointer to attached data;
 *  NULL 	 :not found(thus be careful if you are attaching NULL data on purpose).
 */
void *D_INTERNAL_MESA_hash_sel_with_cb_v2(MESA_hash_tab_v2_t * table, uchar * key, uint size,
								    hash_cb_t *cb, void *arg, int *cb_ret)
{
	uint index;
	hash_elem_v2_t * ptr;
	void *ret;
	
	index = table->key2index(table, key, size);
    D_INTERNAL___MESA_hash_mutex_lock(table,index);
    D_INTERNAL___MESA_hash_eliminate(table,index);/* 2013-09-12 LiJia modify, 先淘汰再查找,否则会将查到的结果淘汰而又返回给了调用者 */
    ptr = D_INTERNAL___MESA_hash_key_search(table,key,size,index);
	if(NULL != ptr){
	    ret = ptr->data;
	    if(HASH_ELIMINATE_ALGO_LRU == table->eliminate_type){
	        ptr->op_time = HASH_TIME_NOW();
	        D_INTERNAL___MESA_hash_time_list_lru(table, ptr, index);
	    }
	    if(cb){
	        *cb_ret = cb(ptr->data, arg);
	    }    
    }else{
        ret = NULL;
	    if(cb){
	        *cb_ret = cb(NULL, arg);
	    }    
    }
    
    D_INTERNAL___MESA_hash_mutex_unlock(table,index);

    return ret;
}

int D_INTERNAL_MESA_hash_iterate_v2(MESA_hash_tab_v2_t * table, void (* func)(uchar * key, uint size, void * data))
{
    int i;
    hash_elem_v2_t * ptr;

    if(NULL == func){
        return 0;
    }
    
    for(i = 0; i < (int)table->size; i++) {
        D_INTERNAL___MESA_hash_mutex_lock(table, i/(table->size/HASH_TABLE_MUTEX_NUM));
    	for(ptr = table->elems[i]; NULL != ptr; ptr = ptr->next)
    		func(ptr->key, ptr->size, ptr->data);
    	D_INTERNAL___MESA_hash_mutex_unlock(table, i/(table->size/HASH_TABLE_MUTEX_NUM));
    }
	
	return 0;
}

int D_INTERNAL_MESA_hash_iterate_v2_2(MESA_hash_tab_v2_t * table, void (* func)(uchar * key, uint size, void * data, void * u), void * user)
{
    int i;
    hash_elem_v2_t * ptr;

    if(NULL == func){
        return 0;
    }
    for(i = 0; i < (int)table->size; i ++) {
        D_INTERNAL___MESA_hash_mutex_lock(table, i/(table->size/HASH_TABLE_MUTEX_NUM));
    	for(ptr = table->elems[i]; NULL != ptr; ptr = ptr->next)
    		func(ptr->key, ptr->size, ptr->data, user);
    	D_INTERNAL___MESA_hash_mutex_unlock(table, i/(table->size/HASH_TABLE_MUTEX_NUM));
    }
	
    return 0;
}

