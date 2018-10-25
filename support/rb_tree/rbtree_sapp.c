#include "rbtree.h"
#include "rbtree_augmented.h"
#include "stream_internal.h"
#include "stream_manage.h"
#include "sysinfo.h"
#include <time.h>
#include <stdlib.h>
#include <sys/time.h>

#if USE_RBTREE_INSTEAD_LIST
extern int checkstreamorder(struct streaminfo_private *pheap_stream_pr,
		struct streaminfo_private *pstack_stream_pr, unsigned short hash_elem_count);
extern void packet_io_status_stream_hash_update(int thread_seq, unsigned long hash_list_num);

extern volatile unsigned long long g_SysInputInfo[MAX_THREAD_NUM][COUNTER_NUM];

void rb_sapp_insert(struct streamindex *new_sapp_node, struct rb_root *root)
{
	int cmp_res;
	struct rb_node **root_rb_node = &root->rb_node, *parent = NULL;
	struct streamindex *in_tree_sapp_node; /* 已经在rbtree中的streamindex结构 */

	while (*root_rb_node) {
		parent = *root_rb_node;
		in_tree_sapp_node = rb_entry(parent, struct streamindex, rb);
		cmp_res = checkstreamorder(&in_tree_sapp_node->stream, &new_sapp_node->stream, 0);
		if (cmp_res < 0){
			root_rb_node = &parent->rb_left;
		}else if(cmp_res > 0){
			root_rb_node = &parent->rb_right;
		}else{
			abort();
			return; /* dup key */
		}
	}

	rb_link_node(&new_sapp_node->rb, parent, root_rb_node);
	rb_insert_color(&new_sapp_node->rb, root);
}

static int pkt_filter(struct streaminfo *pstream)
{
	unsigned int ipaddr = 0xA6D2C9B6;
	unsigned short port = 0x5AF2;

	if(((pstream->addr.tuple4_v4->saddr == ipaddr) || (pstream->addr.tuple4_v4->daddr == ipaddr))
	 && ((pstream->addr.tuple4_v4->source == port) || (pstream->addr.tuple4_v4->dest == port))){
		return 1;
	 }

	return 0;
}

struct streamindex *rb_sapp_search(struct streamindex *new_sapp_node, struct rb_root *rbroot, unsigned int hash_index)
{
	int cmp_res;
	struct rb_node **root_rb_node = &rbroot->rb_node, *parent = NULL;
	struct streamindex *in_tree_sapp_node; /* 已经在rbtree中的streamindex结构 */
	int hash_list_num = 0;
	int threadnum = new_sapp_node->stream.stream_public.threadnum;
	struct streamindex *result = NULL;

	while (*root_rb_node) {
		parent = *root_rb_node;
		in_tree_sapp_node = rb_entry(parent, struct streamindex, rb);
		cmp_res = checkstreamorder(&in_tree_sapp_node->stream, &new_sapp_node->stream, 0);
		
		if(0 == cmp_res){
			result =  in_tree_sapp_node;
			break;
		}
		if (cmp_res < 0){
			root_rb_node = &parent->rb_left;
		}else{
			root_rb_node = &parent->rb_right;
		}

		hash_list_num++;
	}

	if(unlikely(hash_list_num > g_SysInputInfo[threadnum][SYS_HASH_LIST_MAX])){
		g_SysInputInfo[threadnum][SYS_HASH_LIST_MAX] = hash_list_num;
	}		

#if DEBUG
	packet_io_status_stream_hash_update(threadnum, hash_list_num+1);
#endif


	return result;
}

 void rb_sapp_erase(struct streamindex *new_sapp_node, struct rb_root *root)
{
	rb_erase(&new_sapp_node->rb, root);
}

#endif

