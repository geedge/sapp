/* 
    2013-08-16 LiJia add,
    通常不定项数据都是用链表，方便插入、删除等，
    但不方便随机访问, 而且有些应用需要一次性将数据全部一起操作，

    因无法预先知道数组大小，动态增加长度控制也很不方便.
    故本模块实现一个动态可增长、与实际存储内容无关的通用数组结构。

    to do:
    		数组长度可动态减小!
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "dynamic_array.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define DA_MAGIC		(0xDADADADA)

typedef struct{
#if DYNAMIC_ARRAY_DEBUG
	unsigned int magic_start;	/* 用于检测内存溢出被写乱 */
#endif
	int struct_len; 	/* 通用数组中存储的实际结构长度 */
	int array_num;	/* 通用数组中存储的实际结构数量 */
	int array_max;	/* 通用数组中存储的实际结构最大数量 */
	int cur_len;		/* 通用数组占用的实际存储空间 */
	int tot_len;		/* 通用数组占用的全部存储空间, tot_len >= cur_len */
	void *struct_data;	/* 通用数组中存储的实际结构内容头指针 */
#if DYNAMIC_ARRAY_DEBUG
	unsigned int magic_end;		/* 用于检测内存溢出被写乱 */
#endif
}dynamic_array_t;

#define DYNAMIC_EXPAND_NUM          (10) /* 空间不够时,每次动态增长的元素个数 */


/* 
	struct_len  : 通用数组中存储的实际结构长度, 
	array_num	: 通用数组初始元素数量.	
	array_max	: 通用数组最大元素数量，为了安全考虑，防止无限占用内存， 0表示无限.
*/
dynamic_array_handle dynamic_array_init(int struct_len, int array_init_num, int array_max_num)
{
	dynamic_array_t *real_dah;
	if(struct_len <= 0 || array_init_num <= 0 || ((array_max_num != 0) && (array_max_num < array_init_num))){
		return NULL;
	}
	real_dah = (dynamic_array_t *)malloc(sizeof(dynamic_array_t));
	memset(real_dah, 0, sizeof(dynamic_array_t));
	
	real_dah->struct_len = struct_len;
	real_dah->struct_data = calloc(array_init_num, struct_len);
	real_dah->tot_len = array_init_num * struct_len;
	real_dah->array_max = array_max_num;

#if DYNAMIC_ARRAY_DEBUG
	real_dah->magic_start = DA_MAGIC;
	real_dah->magic_end = DA_MAGIC;
#endif

	return (dynamic_array_handle)real_dah;
}

void dynamic_array_destroy(dynamic_array_handle dah, 
                                   dynamic_array_iterate_cb cb, void *cb_arg)
{
    int i, struct_num, struct_len;
    dynamic_array_t *real_dah;
    char *struct_data;

    if(NULL == dah){
        return;
    }

    real_dah = (dynamic_array_t *)dah;

#if DYNAMIC_ARRAY_DEBUG
	if(DA_MAGIC != real_dah->magic_start){
		assert(0);
	}
	if(DA_MAGIC != real_dah->magic_end){
		assert(0);
	}	
#endif

    struct_data = (char *)real_dah->struct_data;
    struct_num = real_dah->array_num;
    struct_len = real_dah->struct_len;
    
    if(cb){
        for(i = 0; i < struct_num; i++){
            cb(i, struct_data, cb_arg);
            struct_data += struct_len;
        }
    }
    real_dah->array_num = 0;
    free(real_dah->struct_data);
    free(real_dah);

}


/*
	return value: 
	-1: error;
	-2: too many items;
	>0: OK,当前数组的总元素数量。 
*/
int dynamic_array_append(dynamic_array_handle dah, void *struct_data, int struct_len)
{
	dynamic_array_t *real_dah = (dynamic_array_t *)dah;
	void *tmp;
	
	if(!dah || !struct_data || real_dah->struct_len != struct_len){
		return -1;
	}

	if((real_dah->array_max != 0) && (real_dah->array_num >= real_dah->array_max)){
		return -2;
	}

#if DYNAMIC_ARRAY_DEBUG
	if(DA_MAGIC != real_dah->magic_start){
		assert(0);
	}
	if(DA_MAGIC != real_dah->magic_end){
		assert(0);
	}	
#endif

	if(real_dah->tot_len < real_dah->cur_len + struct_len){ /* 剩余空间不足 */
#if 1	
		tmp = malloc(real_dah->tot_len + DYNAMIC_EXPAND_NUM*struct_len); /* 每次多追加10个元素长度 */
		memcpy(tmp, real_dah->struct_data, real_dah->cur_len);
		free(real_dah->struct_data);
#else
		tmp = APPD_REALLOC(real_dah->struct_data, real_dah->tot_len + DYNAMIC_EXPAND_NUM*struct_len);
#endif
		real_dah->struct_data = tmp;
		real_dah->tot_len += DYNAMIC_EXPAND_NUM*struct_len;
	}

	memcpy((char *)real_dah->struct_data + real_dah->cur_len, struct_data, struct_len);

	real_dah->cur_len += struct_len;

	return ++real_dah->array_num;
}

/* 功能同dynamic_array_append()类似,但保证无重复数据 
	return value: 
	-1: error;
	-2: too many items;
	-3: duplicate item;
	>0: OK, 当前数组的总元素数量。 
*/
int dynamic_array_append_distinct(dynamic_array_handle dah, void *struct_data, int struct_len)
{
    char *data;
    int i,item_num;
    dynamic_array_t *real_dah = (dynamic_array_t *)dah;

    if(!dah || !struct_data || real_dah->struct_len != struct_len){
        return -1;
    }

    if((real_dah->array_max != 0) && (real_dah->array_num >= real_dah->array_max)){
        return -2;
    }

#if DYNAMIC_ARRAY_DEBUG
	if(DA_MAGIC != real_dah->magic_start){
		assert(0);
	}
	if(DA_MAGIC != real_dah->magic_end){
		assert(0);
	}	
#endif

    data = (char *)real_dah->struct_data;
    item_num = real_dah->array_num;

    for(i = 0; i < item_num; i++){
        if(memcmp(data+i*real_dah->struct_len, struct_data, struct_len) == 0){
            return -3;
        }
    }

    return dynamic_array_append(dah, struct_data, struct_len);	
}

/* 获取第index个元素值,index取值[0, max) */
void *dynamic_array_fetch(dynamic_array_handle dah, int index)
{
	char *data;
	dynamic_array_t *real_dah = (dynamic_array_t *)dah;

	if(NULL == dah){
        return NULL;
	}
	

	if(index >= real_dah->array_num){ /* index从0开始, array_num从1开始计数 */
		return NULL;
	}

	data = (char *)real_dah->struct_data;
	
	return (void *)(data+real_dah->struct_len*index); 
}



/* 当前数组的总元素数量 */
int dynamic_array_get_num(dynamic_array_handle dah)
{
	dynamic_array_t *real_dah = (dynamic_array_t *)dah;

	if(NULL == dah){
        return 0;
	}

#if DYNAMIC_ARRAY_DEBUG
	if(DA_MAGIC != real_dah->magic_start){
		assert(0);
	}
	if(DA_MAGIC != real_dah->magic_end){
		assert(0);
	}	
#endif

	return real_dah->array_num;
}

/* 当前数组的实际存储内容头指针 */
void *dynamic_array_get_data(dynamic_array_handle dah)
{
	dynamic_array_t *real_dah = (dynamic_array_t *)dah;

	if(NULL == dah){
        return NULL;
	}

#if DYNAMIC_ARRAY_DEBUG
	if(DA_MAGIC != real_dah->magic_start){
		assert(0);
	}
	if(DA_MAGIC != real_dah->magic_end){
		assert(0);
	}	
#endif

	return real_dah->struct_data;
}

/* 取动态数组中最后一个元素 */
void *dynamic_array_get_last_item(dynamic_array_handle dah)
{
    int item_num;

    item_num = dynamic_array_get_num(dah);
    if(0 == item_num){
        return NULL;
    }

    return dynamic_array_fetch(dah, item_num-1);
}


/*
    遍历动态数组每个元素.
    return value:
    the return value of "cb";
    
	dynamic_array_cb返回值对于本函数的控制作用:
	-1 :继续遍历，直至数组结束;
	>=0:立即返回.
*/
int dynamic_array_iterate(dynamic_array_handle dah, dynamic_array_iterate_cb cb, void *user_arg)
{
    dynamic_array_t *idah = (dynamic_array_t *)dah;
    int i, struct_num, struct_len;
    char *struct_data;
    int ret = -1;

    if(NULL == dah){
        return -1;
    }

#if DYNAMIC_ARRAY_DEBUG
	if(DA_MAGIC != idah->magic_start){
		assert(0);
	}
	if(DA_MAGIC != idah->magic_end){
		assert(0);
	}	
#endif

    struct_num = idah->array_num;
    struct_data = (char *)idah->struct_data;
    struct_len = idah->struct_len;
    
    for(i = 0; i < struct_num; i++){
        ret = cb(i, struct_data, user_arg);
        if(ret >= 0){
            return ret;
        }
        struct_data += struct_len;
    }
    
    return ret;
}


/* COPY一个新的通用数组，内容和old_dah一样，
   注意: 如果数组中有指针变量，指向其他内存，复制后此指针可用，
         但一旦被free后，新的new_dah中仍会访问旧内存中的脏数据,慎用!
*/
dynamic_array_handle dynamic_array_quick_copy(dynamic_array_handle old_dah)
{
    dynamic_array_t *new_idah, *old_idah;

    old_idah = (dynamic_array_t *)old_dah;

    new_idah = (dynamic_array_t *)dynamic_array_init(old_idah->struct_len, old_idah->array_num, old_idah->array_max);
    if(NULL == new_idah){
        return NULL;
    }

    memcpy(new_idah->struct_data, old_idah->struct_data, old_idah->cur_len);

    return (dynamic_array_handle)new_idah;
}

/*
    完全复制一个新的通用数组，
    由调用者决定，每个struct data如何复制，
    对于"cb"参数，new_data的内存空间由平台申请，调用者只需复制相应变量即可.
*/
dynamic_array_handle dynamic_array_safe_copy(dynamic_array_handle old_dah, dynamic_array_safe_copy_cb cb)
{
    // to do !!!!
    return NULL;
}

#ifdef __cplusplus
}
#endif


