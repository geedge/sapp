#include "avltree.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <string.h>

#define MAX_TREE_NODE_NUM		(31)

static int tree_node_num = 0;
static long long tree_op_times = 0;

static struct avl_tree tree_root;

struct tree_st{
	struct avl_node tree_node;
	long long num;
};

static struct tree_st g_tree_node_buf[MAX_TREE_NODE_NUM];

static int avl_cmp_fun_cb(struct avl_node *cur, struct avl_node *new_node, void *aux)
{
	struct tree_st *test_cur, *test_new;

	test_cur = _get_entry(cur, struct tree_st, tree_node);
	test_new = _get_entry(new_node, struct tree_st, tree_node);

	return test_new->num - test_cur->num;
}

static void *stat_thread(void *arg)
{
	static long long last_op_times = 0;
	
	while(1){
		printf("avl tree op pps:%lld\n", tree_op_times - last_op_times);
		last_op_times = tree_op_times;
		sleep(1);
	}

	return NULL;
}

int main(void)
{
	int i;
	struct avl_node *tmp_node;
	struct tree_st *tmp_st;
	pthread_t pid;
	
	avl_init(&tree_root, NULL);	

	srand(time(NULL));

	memset(g_tree_node_buf, 0, sizeof(g_tree_node_buf));

	/* 使用全局内存, 避免每次动态分配内存 */
	for(i = 0; i < MAX_TREE_NODE_NUM; i++){
		g_tree_node_buf[i].num = random();
		while(avl_insert(&tree_root, &g_tree_node_buf[i].tree_node, avl_cmp_fun_cb) == NULL){
			g_tree_node_buf[i].num = random();
		}
	}

	pthread_create(&pid, NULL, stat_thread, NULL);
	
	while(1){
		tmp_node = avl_first(&tree_root);		/* 删除最小的 */
		avl_remove(&tree_root, tmp_node);
		tmp_st = _get_entry(tmp_node, struct tree_st, tree_node);
		tmp_st->num = rand(); /* 更新数值 */
		while(avl_insert(&tree_root, &tmp_st->tree_node, avl_cmp_fun_cb) == NULL){
			tmp_st->num = rand(); /* 更新数值 */
		}
		tree_op_times++;
	}

	return 0;
}

