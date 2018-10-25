#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <linux/stddef.h>
#include <assert.h>
#include "MESA_list_v2.h"
#include "list_common.h"



extern void D_INTERNAL_list_count_init(void **list_count);
extern void D_INTERNAL_list_count_inc(void **list_count);
extern void D_INTERNAL_list_count_dec(void **list_count);

#if MESA_LIST_CHECK != 0
/*Function:Check the intergrity of the list,to dectect memory mess.
*Input: Queue Head,data check call back function
*Output: return a number below zero,if the queue got a problem,else return 0;
*Author:zhengchao@iie.ac.cn at 20100913
*/
#if 0
static int MESA_q_list_check(const MESA_queue_head_v2_t *qhead_obj,int(*quiddity_check)(const void *))
{
	MESA_list_index_v2_t	*p=NULL, *head=NULL;
//	int linked_ele_number=0;
	int ret=0;
//	return 0;
	if(qhead_obj->listcount==0)
	{
		if(qhead_obj->head!=NULL||qhead_obj->head!=NULL)
		{
			ret=-1;
		}
		goto exit;
	}
	
	if(qhead_obj->head==NULL||qhead_obj->tail==NULL)
	{
		ret=-2;
		goto exit;
	}
	if(qhead_obj->listcount>1){
		if(qhead_obj->head->preele!=NULL||qhead_obj->head->nextele==NULL)
		{
			ret=-3;
			goto exit;
		}
		if(qhead_obj->tail->preele==NULL||qhead_obj->tail->nextele!=NULL)
		{
			ret=-4;
			goto exit;
		}

		head = p = qhead_obj->head;
		p = p->nextele;
		while(p != head)
		{
            if(p == NULL) break;
            if(p == head){
                ret = -5; /* has a cycle */
                goto exit;
            }
            p = p->nextele;
		}
	}
	/*
	pre=qhead_obj->head;
	p=pre->nextele;
	while(p!=NULL){
		linked_ele_number++;
		
		//Is the declared size equal to element linked number;
		if(linked_ele_number > qhead_obj->listcount)
		{
			ret=-5;
			goto exit;
		}
		
		//Is element's preele pointer equal to its preele
		if(pre!=p->preele)
		{
			ret=-6;
			goto exit;
		}
		if(quiddity_check!=NULL){
			if(0>quiddity_check(p->quiddity))
			{
				ret =-7;
				goto exit;
			}
		}
		pre=p;
		p=p->nextele;
	}
	//Is the last element equal to tail
	if(pre!=qhead_obj->tail)
	{
		ret=-8;
		goto exit;
	}
	if(linked_ele_number !=qhead_obj->listcount-1)
	{
		ret=-9;
		goto exit;
	}
	*/
exit:
	if(ret<0)
	{
		return ret;
	}
	else
	{
		return 1;
	}
	
}
#endif

#if 2==MESA_LIST_CHECK
/*Simple check,not raversal*/
static int D_INTERNAL_MESA_q_is_item_in_list_v2(MESA_queue_head_v2_t *qhead_obj, MESA_list_index_v2_t *lindex_obj){
//	MESA_list_index_v2_t* pre=lindex_obj->preele;
//	MESA_list_index_v2_t*next=lindex_obj->nextele;
	MESA_list_index_v2_t*p=NULL;
	int i, num;
	
	if(D_INTERNAL_common_list_empty_careful(qhead_obj)){
		return 0;
    }
	
	p = qhead_obj->nextele;
	num = D_INTERNAL_MESA_get_list_count_v2(qhead_obj);
    i = 0;
	while((p != qhead_obj) && (i <= num))
	{
		if(p == lindex_obj)
		{
			return 1;
		}
		p=p->nextele;
		i++;
	}
	
	return 0;
	
}
#endif

/*every MESA_list_index_v2_t leaves list,its pre and next will be set NULL
 * In Configuration Transmiiter project, not null element will consider in list,
 * pre and next is NULL only if there's one element in list only*/
static int D_INTERNAL_MESA_q_is_item_in_list_quick_v2(MESA_queue_head_v2_t *qhead_obj, MESA_list_index_v2_t *lindex_obj)
{
	//empty list
	if(D_INTERNAL_common_list_empty_careful((struct common_list_index *)qhead_obj)){
		return 0;
	}	

	//have more element
	if(lindex_obj->nextele==NULL || lindex_obj->preele==NULL){
		return 0;
	}
	if(lindex_obj->nextele->preele != lindex_obj){
        return 0;
	}
    if(lindex_obj->preele->nextele != lindex_obj){
        return 0;
	}

	return 1;

}
#endif

void D_INTERNAL_list_count_init(void **list_count)
{
    long *p_c = (long *)list_count;
    *p_c = 0;
}

void D_INTERNAL_list_count_inc(void **list_count)
{
    long *p_c = (long *)list_count;
    long c = *p_c;
    *p_c = c + 1;
}

void D_INTERNAL_list_count_dec(void **list_count)
{
    long *p_c = (long *)list_count;
    long c = *p_c;
    *p_c = c - 1;
}


/*************************** 外部调用接口 ********************************/


/*
    第一次使用MESA_list模块时，必须调用此初始化模块.
*/
int D_INTERNAL_MESA_list_init_v2(MESA_queue_head_v2_t *head)
{
    D_INTERNAL_COMMON_LIST_INIT_HEAD((struct common_list_index *)head);
    D_INTERNAL_list_count_init(&head->quiddity);
    return 0;
}

/* 做为head使用时, "quiddity"做为一个long型变量,用于存储链表元素数量 */
long D_INTERNAL_MESA_get_list_count_v2(const MESA_queue_head_v2_t *head)
{
    return (long)head->quiddity;
}

MESA_list_index_v2_t *D_INTERNAL_MESA_q_read_next_v2(MESA_queue_head_v2_t *head,MESA_list_index_v2_t *lindex_obj)
{
    return (lindex_obj->nextele == head) ? NULL: lindex_obj->nextele;
}

MESA_list_index_v2_t *D_INTERNAL_MESA_q_read_pre_v2(MESA_queue_head_v2_t *head, MESA_list_index_v2_t *lindex_obj)
{
    return (lindex_obj->preele == head) ? NULL: lindex_obj->nextele;
}

MESA_list_index_v2_t *D_INTERNAL_MESA_q_read_head_v2(const MESA_queue_head_v2_t *qhead_obj)
{
    if(D_INTERNAL_common_list_empty_careful((struct common_list_index *)qhead_obj)){
        return NULL;
    }
    return qhead_obj->nextele;
}


MESA_list_index_v2_t *D_INTERNAL_MESA_q_get_head_v2(MESA_queue_head_v2_t *qhead_obj)
{
    MESA_list_index_v2_t *out;
    if(D_INTERNAL_common_list_empty_careful((struct common_list_index *)qhead_obj)){
        return NULL;
    }
    out = qhead_obj->nextele;
    D_INTERNAL_common_list_del((struct common_list_index *)out);
    D_INTERNAL_list_count_dec(&qhead_obj->quiddity);

    return out;
}

MESA_list_index_v2_t *D_INTERNAL_MESA_q_get_tail_v2(MESA_queue_head_v2_t *qhead_obj)
{
    MESA_list_index_v2_t *out;
    if(D_INTERNAL_common_list_empty_careful((struct common_list_index *)qhead_obj)){
        return NULL;
    }
    out = qhead_obj->preele;
    D_INTERNAL_common_list_del((struct common_list_index *)out);
    D_INTERNAL_list_count_dec(&qhead_obj->quiddity);
    
    return out;
}

MESA_list_index_v2_t *D_INTERNAL_MESA_q_join_tail_v2(MESA_queue_head_v2_t *qhead_obj, MESA_list_index_v2_t *lindex_obj)
{
    D_INTERNAL_common_list_add_tail((struct common_list_index *)lindex_obj, (struct common_list_index *)qhead_obj);
    D_INTERNAL_list_count_inc(&qhead_obj->quiddity);
    
    return lindex_obj;
}

MESA_list_index_v2_t *D_INTERNAL_MESA_q_join_head_v2(MESA_queue_head_v2_t *qhead_obj, MESA_list_index_v2_t *lindex_obj)
{
    D_INTERNAL_common_list_add((struct common_list_index *)lindex_obj, (struct common_list_index *)qhead_obj);
    D_INTERNAL_list_count_inc(&qhead_obj->quiddity);
    
    return lindex_obj;
}

MESA_list_index_v2_t *D_INTERNAL_MESA_q_join_list_n_v2(MESA_queue_head_v2_t *qhead_obj, MESA_list_index_v2_t *place_next, MESA_list_index_v2_t *new_obj)
{
    D_INTERNAL_common_list_add((struct common_list_index *)new_obj, (struct common_list_index *)place_next);
    D_INTERNAL_list_count_inc(&qhead_obj->quiddity);
    return new_obj;
}

MESA_list_index_v2_t *D_INTERNAL_MESA_q_join_list_p_v2(MESA_queue_head_v2_t *qhead_obj, MESA_list_index_v2_t *new_obj, MESA_list_index_v2_t *place_pre)
{
    D_INTERNAL_common_list_add((struct common_list_index *)new_obj, (struct common_list_index *)place_pre->preele);
    D_INTERNAL_list_count_inc(&qhead_obj->quiddity);
    return new_obj;
}

MESA_list_index_v2_t *D_INTERNAL_MESA_q_leave_list_v2(MESA_queue_head_v2_t *qhead_obj, MESA_list_index_v2_t *lindex_obj)
{
#if 1==MESA_LIST_CHECK
    if(0 == D_INTERNAL_MESA_q_is_item_in_list_quick_v2(qhead_obj, lindex_obj)){
        //return NULL;
        assert(0); //critical
    }
#elif 2==MESA_LIST_CHECK
    if(0 == D_INTERNAL_MESA_q_is_item_in_list_v2(qhead_obj, lindex_obj)){
        //return NULL;
        assert(0); //critical
    }
#endif    
    D_INTERNAL_common_list_del((struct common_list_index *)lindex_obj);
    D_INTERNAL_list_count_dec(&qhead_obj->quiddity);

    return lindex_obj;
}

MESA_list_index_v2_t *D_INTERNAL_MESA_q_move_head_v2(MESA_queue_head_v2_t *qhead_obj, MESA_list_index_v2_t *lindex_obj)
{
#if 1==MESA_LIST_CHECK
    if(0 == D_INTERNAL_MESA_q_is_item_in_list_quick_v2(qhead_obj, lindex_obj)){
        //return NULL;
        assert(0); //critical
    }
#elif 2==MESA_LIST_CHECK
    if(0 == D_INTERNAL_MESA_q_is_item_in_list_v2(qhead_obj, lindex_obj)){
        //return NULL;
        assert(0); //critical
    }
#endif    
    D_INTERNAL_common_list_move((struct common_list_index *)lindex_obj, (struct common_list_index *)qhead_obj);

    return lindex_obj;
}

MESA_list_index_v2_t *D_INTERNAL_MESA_q_move_tail_v2(MESA_queue_head_v2_t *qhead_obj, MESA_list_index_v2_t *lindex_obj)
{
#if 1==MESA_LIST_CHECK
    if(0 == D_INTERNAL_MESA_q_is_item_in_list_quick_v2(qhead_obj,lindex_obj)){
        //return NULL;
        assert(0); //critical
    }
#elif 2==MESA_LIST_CHECK
    if(0 == D_INTERNAL_MESA_q_is_item_in_list_v2(qhead_obj, lindex_obj)){
        //return NULL;
        assert(0); //critical
    }
#endif    
    D_INTERNAL_common_list_move_tail((struct common_list_index *)lindex_obj, (struct common_list_index *)qhead_obj);

    return lindex_obj;
}

void D_INTERNAL_MESA_q_destroy_v2(MESA_queue_head_v2_t *qhead_obj, void (* cb)(MESA_list_index_v2_t *))
{
    MESA_list_index_v2_t *del;

    while(!D_INTERNAL_common_list_empty_careful((struct common_list_index *)qhead_obj)){
        del = qhead_obj->nextele;
        D_INTERNAL_common_list_del((struct common_list_index *)del);
        if(del->quiddity && cb){
            cb(del);
        }
    }

    return;
}


