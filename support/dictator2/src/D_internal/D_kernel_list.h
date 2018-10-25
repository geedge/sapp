#ifndef _D_KERNEL_LIST_
#define _D_KERNEL_LIST_

#include <pthread.h>

struct D_kernel_list_head{
    struct D_kernel_list_head *next, *prev;
};

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({			 \
	const typeof( ((type *)0)->member ) *__mptr = (ptr); \
	(type *)( (char *)__mptr - offsetof(type,member) );})
#endif


#define D_kernel_list_entry(ptr, type, member)  container_of(ptr, type, member)

#define LIST_IS_EMPTY(_head) (((_head)->next == (_head)) ? 1 : 0 )

#define D_kernel_list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)

void D_kernel_list_init(struct D_kernel_list_head *head);
void D_kernel_list_add_head(struct D_kernel_list_head *head, struct D_kernel_list_head *new_node);
void D_kernel_list_add_tail(struct D_kernel_list_head *head,struct D_kernel_list_head *new_node);
void D_kernel_list_delete(struct D_kernel_list_head *head,struct D_kernel_list_head *del);
void D_kernel_list_move_head(struct D_kernel_list_head *head, struct D_kernel_list_head *node);
void D_kernel_list_destroy(struct D_kernel_list_head *head, void (*my_list_free)(struct D_kernel_list_head *del));
struct D_kernel_list_head * D_kernel_list_get_head(struct D_kernel_list_head *head);
struct D_kernel_list_head * D_kernel_list_get_tail(struct D_kernel_list_head *head);

#endif

