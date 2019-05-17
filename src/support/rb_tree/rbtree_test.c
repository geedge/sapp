#include "rbtree.h"
#include "rbtree_augmented.h"
#include "sapp_api.h"
#include "sapp_private_api.h"

#define NODES       100
#define PERF_LOOPS  100000
#define CHECK_LOOPS 100

#ifndef  u32
#define u32 unsigned int 
#endif

struct test_node {
	struct rb_node rb;
	u32 key;

	/* following fields used for testing augmented rbtree functionality */
	u32 val;
	u32 augmented;
};

static struct rb_root root = RB_ROOT;
static struct test_node nodes[NODES];

static int rnd;

static void insert(struct test_node *node, struct rb_root *root)
{
	struct rb_node **new = &root->rb_node, *parent = NULL;
	u32 newkey = node->key;
	struct test_node *in_tree_node;

	while (*new) {
		parent = *new;
		in_tree_node = rb_entry(parent, struct test_node, rb);
		if (newkey < in_tree_node->key){
			new = &parent->rb_left;
		}else if(newkey > in_tree_node->key){
			new = &parent->rb_right;
		}else{
			return; /* dup key */
		}
	}

	rb_link_node(&node->rb, parent, new);
	rb_insert_color(&node->rb, root);
}


static struct test_node *search(int search_key)
{
	struct rb_node **new = &root.rb_node, *parent = NULL;
	struct test_node *in_tree_node;

	while (*new) {
		parent = *new;
		in_tree_node = rb_entry(parent, struct test_node, rb);
		if(search_key == in_tree_node->key){
			return in_tree_node;
		}
		if (search_key < in_tree_node->key){
			new = &parent->rb_left;
		}else{
			new = &parent->rb_right;
		}
	}

	return NULL;
}

static inline void __erase(struct test_node *node, struct rb_root *root)
{
	rb_erase(&node->rb, root);
}

static inline void erase(int erase_key, struct rb_root *root)
{
	struct test_node *erase_node;

	erase_node = search(erase_key);
	if(NULL == erase_node){
		abort();
		return;
	}
	
	rb_erase(&erase_node->rb, root);
}

static inline u32 augment_recompute(struct test_node *node)
{
	u32 max = node->val, child_augmented;
	if (node->rb.rb_left) {
		child_augmented = rb_entry(node->rb.rb_left, struct test_node, rb)->augmented;
		if (max < child_augmented)
			max = child_augmented;
	}
	if (node->rb.rb_right) {
		child_augmented = rb_entry(node->rb.rb_right, struct test_node, rb)->augmented;
		if (max < child_augmented)
			max = child_augmented;
	}
	return max;
}

RB_DECLARE_CALLBACKS(static, augment_callbacks, struct test_node, rb,u32, augmented, augment_recompute)

static void insert_augmented(struct test_node *node, struct rb_root *root)
{
	struct rb_node **new = &root->rb_node, *rb_parent = NULL;
	u32 key = node->key;
	u32 val = node->val;
	struct test_node *parent;

	while (*new) {
		rb_parent = *new;
		parent = rb_entry(rb_parent, struct test_node, rb);
		if (parent->augmented < val)
			parent->augmented = val;
		if (key < parent->key)
			new = &parent->rb.rb_left;
		else
			new = &parent->rb.rb_right;
	}

	node->augmented = val;
	rb_link_node(&node->rb, rb_parent, new);
	rb_insert_augmented(&node->rb, root, &augment_callbacks);
}

static void erase_augmented(struct test_node *node, struct rb_root *root)
{
	rb_erase_augmented(&node->rb, root, &augment_callbacks);
}

static void init(void)
{
	int i;
	for (i = 0; i < NODES; i++) {
		nodes[i].key = rand();
		nodes[i].val = rand();
	}
}

static int is_red(struct rb_node *rb)
{
	return !(rb->__rb_parent_color & 1);
}

static int black_path_count(struct rb_node *rb)
{
	int count;
	for (count = 0; rb; rb = rb_parent(rb))
		count += !is_red(rb);
	return count;
}

static void check(int nr_nodes)
{
	struct rb_node *rb;
	int count = 0;
	int blacks;
	u32 prev_key = 0;

	for (rb = rb_first(&root); rb; rb = rb_next(rb)) {
		struct test_node *node = rb_entry(rb, struct test_node, rb);
		//WARN_ON_ONCE(node->key < prev_key);
		//WARN_ON_ONCE(is_red(rb) && (!rb_parent(rb) || is_red(rb_parent(rb))));
		if (!count)
			blacks = black_path_count(rb);
		else{
			//WARN_ON_ONCE((!rb->rb_left || !rb->rb_right) && blacks != black_path_count(rb));
		}
		prev_key = node->key;
		count++;
	}
	//WARN_ON_ONCE(count != nr_nodes);
}

static void check_augmented(int nr_nodes)
{
	struct rb_node *rb;

	check(nr_nodes);
	for (rb = rb_first(&root); rb; rb = rb_next(rb)) {
		struct test_node *node = rb_entry(rb, struct test_node, rb);
		//WARN_ON_ONCE(node->augmented != augment_recompute(node));
	}
}

static int rbtree_test_init(void)
{
	int i, j;
	time_t time1, time2, time3;

	printf("rbtree testing\n");

	rnd = random();
	init();

	time1 = time(NULL);

	for (i = 0; i < PERF_LOOPS; i++) {
		for (j = 0; j < NODES; j++)
			insert(nodes + j, &root);
		for (j = 0; j < NODES; j++)
			__erase(nodes + j, &root);
	}

	time2 = time(NULL);
	time3 = time2 - time1;

	printf(" -> %llu cycles\n", (unsigned long long)time3);

	for (i = 0; i < CHECK_LOOPS; i++) {
		init();
		for (j = 0; j < NODES; j++) {
			check(j);
			insert(nodes + j, &root);
		}
		for (j = 0; j < NODES; j++) {
			check(NODES - j);
			__erase(nodes + j, &root);
		}
		check(0);
	}

	printf("augmented rbtree testing\n");

	init();

	time1 = time(NULL);

	for (i = 0; i < PERF_LOOPS; i++) {
		for (j = 0; j < NODES; j++)
			insert_augmented(nodes + j, &root);
		for (j = 0; j < NODES; j++)
			erase_augmented(nodes + j, &root);
	}

	time2 = time(NULL);
	time3 = time2 - time1;

	//time3 = div_u64(time, PERF_LOOPS);
	printf(" -> %llu cycles\n", (unsigned long long)time3);

	for (i = 0; i < CHECK_LOOPS; i++) {
		init();
		for (j = 0; j < NODES; j++) {
			check_augmented(j);
			insert_augmented(nodes + j, &root);
		}
		for (j = 0; j < NODES; j++) {
			check_augmented(NODES - j);
			erase_augmented(nodes + j, &root);
		}
		check_augmented(0);
	}

	return 0; /* Fail will directly unload the module */
}

int main(void)
{	
#define OP_NUM	(1000000)

	int i;
	struct test_node *node;
	struct timeval begin_time, end_time;
	
	srand(time(NULL));

	//rbtree_test_init();

	struct test_node *new_nodes = calloc(OP_NUM, sizeof(struct test_node));

	for(i = 0; i < OP_NUM; i++){
		new_nodes[i].key = i;
		new_nodes[i].val = i;
	}

gettimeofday(&begin_time, NULL);

	for( i = 0; i < OP_NUM; i++){
		insert(&new_nodes[i], &root);
	}
gettimeofday(&end_time, NULL);

printf("insert use time in ms:%lld\n", (end_time.tv_sec * 1000 + end_time.tv_usec/1000) - (begin_time.tv_sec * 1000 + begin_time.tv_usec/1000) );

gettimeofday(&begin_time, NULL);
	for(i = OP_NUM - 1 ; i >= 0 ; i--){
		node = search(i);
		if(NULL == node){
			printf("not found key=1!\n");
			abort();
		}else{
			//printf("bingo! key =1\n");
		}
	}
gettimeofday(&end_time, NULL);
printf("search use time in ms:%lld\n", (end_time.tv_sec * 1000 + end_time.tv_usec/1000) - (begin_time.tv_sec * 1000 + begin_time.tv_usec/1000) );



gettimeofday(&begin_time, NULL);
	for(i = 0 ; i < OP_NUM; i++){
		erase(i,&root);
	}
gettimeofday(&end_time, NULL);
printf("erase use time in ms:%lld\n", (end_time.tv_sec * 1000 + end_time.tv_usec/1000) - (begin_time.tv_sec * 1000 + begin_time.tv_usec/1000) );
	return 0;
}

