#ifndef _LIB_HASH_H_INCLUDED_
#define _LIB_HASH_H_INCLUDED_


/*
 * general purpose hash table implementation.
 *
 * xiang hong
 * 2002-07-28
 *History:
 *2012-03-23 zhengchao add thread safe option and link expire feature;
 */



#include <errno.h>
#include <string.h>
#include <pthread.h>
#include "MESA_list_v2.h"
#include "list_common.h"
#include "../internal_mp.h"
#define MESA_HASH_DEBUG			(0)

#if MESA_HASH_DEBUG
#define HASH_INLINE 
#else
#define HASH_INLINE 			inline
#endif


/* 
	此宏定义的作用是取当前时间，可以不是绝对时间，比如一个每隔1秒自增的数，
	为了减少调用time(NULL)函数的次数.
	推荐做法: 
		新建一个线程，对某个变量每隔一秒自增一次.
*/
#if 1
#define HASH_TIME_NOW()        	time(NULL) 
#else
extern volatile unsigned int G_TIMER; /* 此变量在另一个线程中每隔1秒自增一次 */
#define HASH_TIME_NOW()        	(time_t)G_TIMER  
#endif

#ifndef uchar
#define uchar	unsigned char
#endif
#ifndef uint
#define uint	unsigned int
#endif

#define HASH_THRESHOLD_MAX			65536
#define HASH_THRESHOLD_MIN			0
#define HASH_THRESHOLD_MAX_DELTA	32768
#define HASH_THRESHOLD_MIN_DELTA	16

#define HASH_ELIMINATE_ALGO_FIFO	(0) /* by default */
#define HASH_ELIMINATE_ALGO_LRU		(1)

struct __hash_tab_v2;

/*
 * hash key compare function prototype, see hash_key_comp().
 * return value:
 *      0:key1 and key2 are equal;
 *  other:key1 and key2 not equal. 
 */
typedef int key_comp_t(uchar * key1, uint size1, uchar * key2, uint size2);

/*
 * hash key->index computing function prototype, see hash_key2index().
 */
typedef uint key2index_t(struct __hash_tab_v2 * tab, uchar * key, uint size);

typedef int hash_cb_t(void *data, void *arg);

/*
 * hash element structure.
 *
 * key : a copy of key;
 * size: size of key;
 * hash_index: index which use this key and key2index_t() calculated;
 * data: pointer to attached data;
 * prev, next: pointer to prev and next item;
 */
typedef struct struct_hash_elem {
	uchar  *key;
	void   *data;
	uint   size;
	uint   hash_index;
	time_t op_time;
	struct struct_hash_elem *prev;
	struct struct_hash_elem *next;
	MESA_list_index_v2_t list_node;
} hash_elem_v2_t;

/*
 * hash structure.
 *
 * size: number of slots;
 * key_comp: pointer to the function that compares 2 keys;
 * key2index: pointer to the function that computes index from key;
 * expire: pointer to the function that do somthing when data expired;
 * free: pointer to the function that cleans up attached data;
 * elems: array of slots;
 * elem_count: number of items;
 * threshold_lo, threshold_hi: low and high threshold; when elem_count reaches
 * 	one of them, an iteration will be launched to clean up expired items;
 */
typedef struct __hash_tab_v2 {
	uint size;
	uint is_thread_safe;
	key_comp_t * key_comp;
	key2index_t * key2index;
	void (* expire)(void * data);
	void (* free)(void * data);
	hash_elem_v2_t ** elems;
	unsigned int  max_elem_num;
	volatile uint elem_count;
	//uint threshold_lo;
	//uint threshold_hi;
	int  eliminate_type;
	int  expire_time;
	pthread_mutex_t *htable_mutex;
	//MESA_queue_head_t *hlist_head;
	MESA_list_index_v2_t *hlist_head;
	IMP_t* p_mempool;
} MESA_hash_tab_v2_t;

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
int D_INTERNAL_MESA_hash_create_v2(MESA_hash_tab_v2_t * table,
                                    uint is_thread_safe ,
                                    uint size,
                                    uint max_elem_num,
                                    key_comp_t * key_comp, 
                                    key2index_t * key2index,
                                    void (* data_free)(void *),
                                    void (* data_expire)(void *),
                                    int eliminate_type,
                                    int expire_time,
                                    IMP_t * mempool);

/*
 * name: hash_destroy
 * functionality: cleans up hash structure, frees memory occupied;
 * param:
 * 	table: who is the victim;
 * 	func: callback function to clean up data attached to hash items;
 * returns:
 * 	always returns 0;
 */
int D_INTERNAL_MESA_hash_destroy_v2(MESA_hash_tab_v2_t * table, void (* func)(void *));

/*
 * name: hash_add
 * functionality: adds item to table, call hash_expire() if elem_count gets
 * 	bigger than threshold_hi, and adjust threshold;
 * param:
 * 	table: to which table do you want to add;
 * 	key: what is the label;
 * 	size: how long is the label;
 * 	data: what data do you want to attach;
 * returns:
 *	>0 success,return hash elems' linklist size
 * 	-1, duplicates found and can't add this one;
 * 	-2, memory failure;
 */
int D_INTERNAL_MESA_hash_add_v2(MESA_hash_tab_v2_t * table, uchar * key, uint size, void * data);

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
                                void (* func)(void *));

/*
 * name: hash_sel
 * functionality: selects item from table;
 * param:
 * 	table: from which table do you want to select;
 * 	key  : what is the label;
 * 	size : how long is the label;
 *
 * return:
 *  not NULL :pointer to attached data;
 *  NULL 	 :not found(thus be careful if you are attaching NULL data on purpose).
 */
void * D_INTERNAL_MESA_hash_sel_v2(MESA_hash_tab_v2_t * table, uchar * key, uint size);

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
                                                hash_cb_t *cb, void *arg, int *cb_ret);

/*
 * name: hash_iterate
 * functionality: iterates each hash item;
 * params:
 * 	table: what table is to be iterated;
 * 	func: what do you want to do to each attached data item;
 * returns:
 * 	0: iterates all items;
 * -3: can't get lock in non-block mode;
 */
int D_INTERNAL_MESA_hash_iterate_v2(MESA_hash_tab_v2_t * table, void (* func)(uchar * key, uint size, void * data));
int D_INTERNAL_MESA_hash_iterate_v2_2(MESA_hash_tab_v2_t * table, void (* func)(uchar * key, uint size, void * data, void * u), void * user);

#if 0
/*
 * name: hash_expire
 * functionality: iterates each item and deletes those that are expired;
 * params:
 * 	table: what table do you want to check;
 * returns:
 * 	always 0;
 */
int MESA_hash_expire(MESA_hash_tab_v2_t * table);
#endif

#endif	/* _LIB_HASH_H_INCLUDED_ */


