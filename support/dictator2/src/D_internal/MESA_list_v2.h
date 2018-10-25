#ifndef _MESA_LIST_V2_H_
#define _MESA_LIST_V2_H_


#define MESA_LIST_CHECK (1) /* 0:no check; 1:quick check; 2:careful check */

typedef struct list_index_v2{
	struct list_index_v2	*nextele;
	struct list_index_v2	*preele;
	void			    *quiddity;
}MESA_list_index_v2_t;

typedef struct list_index_v2 MESA_queue_head_v2_t;


/*
    第一次使用MESA_list模块时，必须调用此初始化模块!!!
*/
int D_INTERNAL_MESA_list_init_v2(MESA_queue_head_v2_t *head);

long D_INTERNAL_MESA_get_list_count_v2(const MESA_queue_head_v2_t *head);
MESA_list_index_v2_t *D_INTERNAL_MESA_q_read_head_v2(const MESA_queue_head_v2_t *qhead_obj);
MESA_list_index_v2_t *D_INTERNAL_MESA_q_get_head_v2(MESA_queue_head_v2_t *qhead_obj);
MESA_list_index_v2_t *D_INTERNAL_MESA_q_get_tail_v2(MESA_queue_head_v2_t *qhead_obj);
MESA_list_index_v2_t *D_INTERNAL_MESA_q_join_tail_v2(MESA_queue_head_v2_t *qhead_obj, MESA_list_index_v2_t *lindex_obj);
MESA_list_index_v2_t *D_INTERNAL_MESA_q_join_head_v2(MESA_queue_head_v2_t *qhead_obj, MESA_list_index_v2_t *lindex_obj);
MESA_list_index_v2_t *D_INTERNAL_MESA_q_leave_list_v2(MESA_queue_head_v2_t *qhead_obj, MESA_list_index_v2_t *lindex_obj);
MESA_list_index_v2_t *D_INTERNAL_MESA_q_move_head_v2(MESA_queue_head_v2_t *qhead_obj, MESA_list_index_v2_t *lindex_obj);
MESA_list_index_v2_t *D_INTERNAL_MESA_q_move_tail_v2(MESA_queue_head_v2_t *qhead_obj, MESA_list_index_v2_t *lindex_obj);
void D_INTERNAL_MESA_q_destroy_v2(MESA_queue_head_v2_t *qhead_obj, void (* cb)(MESA_list_index_v2_t *));

/* insert "new_obj" between "op_place" and "op_place->nextele" */
MESA_list_index_v2_t *D_INTERNAL_MESA_q_join_list_n_v2(MESA_queue_head_v2_t *qhead_obj, MESA_list_index_v2_t *op_place, MESA_list_index_v2_t *new_obj);

/* insert "new_obj" between "op_place->preele" and "op_place" */
MESA_list_index_v2_t *D_INTERNAL_MESA_q_join_list_p_v2(MESA_queue_head_v2_t *qhead_obj, MESA_list_index_v2_t *new_obj, MESA_list_index_v2_t *op_place);

MESA_list_index_v2_t *D_INTERNAL_MESA_q_read_next_v2(MESA_queue_head_v2_t *qhead_obj, MESA_list_index_v2_t *lindex_obj);
MESA_list_index_v2_t *D_INTERNAL_MESA_q_read_pre_v2(MESA_queue_head_v2_t *qhead_obj, MESA_list_index_v2_t *lindex_obj);

#endif


