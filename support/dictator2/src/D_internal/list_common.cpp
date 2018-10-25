#include <stdio.h>
#include "list_common.h"


/*************************** 内部实现接口 ********************************/

/*
 * Simple doubly linked list implementation.
 *
 * Some of the internal functions ("__xxx") are useful when
 * manipulating whole lists rather than single entries, as
 * sometimes we already know the next/prev entries and we can
 * generate better code by using them directly rather than
 * using the generic single-entry routines.
 */

void D_INTERNAL_COMMON_LIST_INIT_HEAD(struct common_list_index *head)
{
	head->nextele = head;
	head->preele = head;
}


/*
 * Insert a new entry between two known consecutive entries.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void D_INTERNAL___common_list_add(struct common_list_index *new_list,
			      struct common_list_index *prev,
			      struct common_list_index *next)
{
	next->preele = new_list;
	new_list->nextele = next;
	new_list->preele = prev;
	prev->nextele = new_list;
}

/**
 * list_add - add a new entry
 * @new: new entry to be added
 * @head: list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 * lijia comment: list_add()把新节点插在head与head->next之间.
 */
void D_INTERNAL_common_list_add(struct common_list_index *new_list, struct common_list_index *head)
{
	D_INTERNAL___common_list_add(new_list, head, head->nextele);
}


/**
 * list_add_tail - add a new entry
 * @new: new entry to be added
 * @head: list head to add it before
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 * lijia comment: list_add_tail()把新节点插在head与head->prev之间.
 */
void D_INTERNAL_common_list_add_tail(struct common_list_index *new_list, struct common_list_index *head)
{
	D_INTERNAL___common_list_add(new_list, head->preele, head);
}

/*
 * Delete a list entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void D_INTERNAL___common_list_del(struct common_list_index * prev, struct common_list_index * next)
{
	next->preele = prev;
	prev->nextele = next;
}

static inline void D_INTERNAL___common_list_del_entry(struct common_list_index *entry)
{
	D_INTERNAL___common_list_del(entry->preele, entry->nextele);
	entry->nextele = NULL;
	entry->preele = NULL;
}

/**
 * list_del - deletes entry from list.
 * @entry: the element to delete from the list.
 * Note: list_empty() on entry does not return true after this, the entry is
 * in an undefined state.
 */

void D_INTERNAL_common_list_del(struct common_list_index *entry)
{
	D_INTERNAL___common_list_del(entry->preele, entry->nextele);
	entry->nextele = NULL;
	entry->preele = NULL;
}


/**
 * list_move - delete from one list and add as another's head
 * @list: the entry to move
 * @head: the head that will precede our entry
 */
void D_INTERNAL_common_list_move(struct common_list_index *list, struct common_list_index *head)
{
	D_INTERNAL___common_list_del_entry(list);
	D_INTERNAL_common_list_add(list, head);
}

/**
 * list_move_tail - delete from one list and add as another's tail
 * @list: the entry to move
 * @head: the head that will follow our entry
 */
void D_INTERNAL_common_list_move_tail(struct common_list_index *list, struct common_list_index *head)
{
	D_INTERNAL___common_list_del_entry(list);
	D_INTERNAL_common_list_add_tail(list, head);
}

#if 0
/**
 * list_empty - tests whether a list is empty
 * @head: the list to test.
 */
static int list_empty(const struct common_list_index *head)
{
	return head->nextele == head;
}
#endif

/**
 * list_empty_careful - tests whether a list is empty and not being modified
 * @head: the list to test
 *
 * Description:
 * tests whether a list is empty _and_ checks that no other CPU might be
 * in the process of modifying either member (next or prev)
 *
 * NOTE: using list_empty_careful() without synchronization
 * can only be safe if the only activity that can happen
 * to the list entry is list_del_init(). Eg. it cannot be used
 * if another CPU could re-list_add() it.
 */
int D_INTERNAL_common_list_empty_careful(const struct common_list_index *head)
{
	struct common_list_index *next = head->nextele;
	return (next == head) && (next == head->preele);
}

