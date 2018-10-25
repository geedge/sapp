#ifndef _LIST_COMMON_H_
#define _LIST_COMMON_H_

struct common_list_index{
	struct common_list_index	*nextele;
	struct common_list_index	*preele;
};

void D_INTERNAL_COMMON_LIST_INIT_HEAD(struct common_list_index *head);
int D_INTERNAL_common_list_empty_careful(const struct common_list_index *head);
void D_INTERNAL_common_list_add(struct common_list_index *new_list, struct common_list_index *head);
void D_INTERNAL_common_list_add_tail(struct common_list_index *new_list, struct common_list_index *head);
void D_INTERNAL_common_list_del(struct common_list_index *entry);
void D_INTERNAL_common_list_move(struct common_list_index *list, struct common_list_index *head);
void D_INTERNAL_common_list_move_tail(struct common_list_index *list, struct common_list_index *head);

#endif

