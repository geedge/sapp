#include <stdio.h>
#include <assert.h>
#include "D_kernel_list.h"

void D_kernel_list_init(struct D_kernel_list_head *head)
{
    assert(head);
    head->next = head;
    head->prev = head;
}

void D_kernel_list_destroy(struct D_kernel_list_head *head,\
                     void (*my_list_free_cb)(struct D_kernel_list_head *del))
{
    struct D_kernel_list_head *cur, *next;

    assert(head && my_list_free_cb);

    cur = head->next;
    while(head != cur)
    {
        next = cur->next;
        my_list_free_cb(cur);
        cur = next;
    } 
}

inline static void __D_kernel_list_delete(struct D_kernel_list_head *prev, struct D_kernel_list_head *next)
{
    next->prev = prev;
    prev->next = next;
}

void D_kernel_list_delete(struct D_kernel_list_head *head,struct D_kernel_list_head *del)
{
    __D_kernel_list_delete(del->prev, del->next);
}

inline static void __D_kernel_list_insert(struct D_kernel_list_head *new_node, 
        struct D_kernel_list_head *prev, struct D_kernel_list_head *next)
{
    next->prev = new_node;
    new_node->next = next;
    new_node->prev = prev;
    prev->next = new_node;
}

void D_kernel_list_add_head(struct D_kernel_list_head *head, 
                           struct D_kernel_list_head *new_node)
{
    __D_kernel_list_insert(new_node, head, head->next);
}

void D_kernel_list_add_tail(struct D_kernel_list_head *head, 
                           struct D_kernel_list_head *new_node)
{
	__D_kernel_list_insert(new_node, head->prev, head);
}

struct D_kernel_list_head * D_kernel_list_get_head(struct D_kernel_list_head *head)
{
	struct D_kernel_list_head*p=NULL;
	if(LIST_IS_EMPTY(head))
	{
		return NULL;
	}
	p=head->next;
    D_kernel_list_delete(head, p);
	return p;
}
struct D_kernel_list_head * D_kernel_list_get_tail(struct D_kernel_list_head *head)
{
	struct D_kernel_list_head*p=NULL;
	if(LIST_IS_EMPTY(head))
	{
		return NULL;
	}
	p=head->prev;
    D_kernel_list_delete(head, p);
	return p;
}
void D_kernel_list_move_head(struct D_kernel_list_head *head,
                              struct D_kernel_list_head *node)
{
    D_kernel_list_delete(node->prev, node->next);
    __D_kernel_list_insert(node, head, head->next); 
}

