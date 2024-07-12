#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_declaration.h"
#include "MESA_htable.h"
#include "MESA_list.h"

#define STREAM_BRIDGE_MAGIC_SUCC (0x62726765) 

typedef struct{	
	int magic_num;
	int bridge_id;
	char bridge_name[NAME_MAX];
	stream_bridge_free_cb_t *async_data_free_cb;
	MESA_list_t sync_callback_fun_list;
}stream_bridge_manage_t;

struct stream_bridge_item{
	long long value; 
	char valid_flag;
}__attribute__((packed, aligned(1)));
typedef struct stream_bridge_item stream_bridge_item_t;


static int g_stream_bridge_actual_num;
static stream_bridge_manage_t g_stream_bridge_manage[STREAM_BRIDGE_MAX_NUM];

static MESA_htable_handle g_stream_bridge_name2id_htable;

static void _stream_bridge_name2id_htable_free_cb(void *data)
{
	if(data){
		sapp_mem_free(SAPP_MEM_FIX_GLOBAL_STREAM, -1, data);
	}
}

static MESA_htable_handle stream_bridge_name2id_htable_create(void)
{
	MESA_htable_handle htable;
	int ret, opt_int;
	
	htable = MESA_htable_born();
	assert(htable != NULL);

	opt_int = 0;
	MESA_htable_set_opt(htable, MHO_THREAD_SAFE, &opt_int, sizeof(int));

	opt_int = 1024 * 32;
	MESA_htable_set_opt(htable, MHO_HASH_SLOT_SIZE, &opt_int, sizeof(int));

	opt_int = 1000;
	MESA_htable_set_opt(htable, MHO_HASH_MAX_ELEMENT_NUM, &opt_int, sizeof(int));

	opt_int = 0;
	MESA_htable_set_opt(htable, MHO_EXPIRE_TIME, &opt_int, sizeof(int));

	opt_int = 0;
	MESA_htable_set_opt(htable, MHO_AUTO_UPDATE_TIME, &opt_int, sizeof(int));

	opt_int = 0;
	MESA_htable_set_opt(htable, MHO_SCREEN_PRINT_CTRL, &opt_int, sizeof(int));

	opt_int = HASH_ELIMINATE_ALGO_FIFO;
	MESA_htable_set_opt(htable, MHO_ELIMIMINATE_TYPE, &opt_int, sizeof(int));

	MESA_htable_set_opt(htable, MHO_CBFUN_DATA_FREE, _stream_bridge_name2id_htable_free_cb, sizeof(void *));
	
	ret = MESA_htable_mature(htable);
	if(ret < 0){
		return NULL;
	}

	return htable;
}


const char *stream_bridge_id_to_name(int bridge_id)
{
	if((bridge_id < 0) || (bridge_id >= g_stream_bridge_actual_num)){
		return NULL;
	}

	return g_stream_bridge_manage[bridge_id].bridge_name;
}


static int stream_bridge_name_to_id(const char *bridge_name)
{
	int *bridge_id;

	bridge_id = (int *)MESA_htable_search(g_stream_bridge_name2id_htable, (const unsigned char *)bridge_name, strlen(bridge_name));
	if(NULL == bridge_id){
		return -1;
	}

	return *bridge_id;
}

static int stream_bridege_create_new_bridge(const char *bridge_name)
{
	int *bridge_id, ret;

	bridge_id = (int *)sapp_mem_calloc(SAPP_MEM_FIX_GLOBAL_STREAM, -1, sizeof(int));

	*bridge_id = g_stream_bridge_actual_num;

	ret = MESA_htable_add(g_stream_bridge_name2id_htable, (const unsigned char *)bridge_name, strlen(bridge_name), (void *)bridge_id);
	if(ret < 0){
		free(bridge_id);
		sapp_runtime_log(RLOG_LV_FATAL, "stream_bridge_build() error, bridge name '%s' already exist!", bridge_name);
		return -1;
	}

	memset(&g_stream_bridge_manage[g_stream_bridge_actual_num], 0, sizeof(stream_bridge_manage_t));
	g_stream_bridge_manage[g_stream_bridge_actual_num].magic_num = STREAM_BRIDGE_MAGIC_SUCC;
	g_stream_bridge_manage[g_stream_bridge_actual_num].bridge_id = g_stream_bridge_actual_num;

	size_t bridge_name_length = strlen(bridge_name);
	//strncpy(g_stream_bridge_manage[g_stream_bridge_actual_num].bridge_name,bridge_name, bridge_name_length);
	sapp_strlcpy(g_stream_bridge_manage[g_stream_bridge_actual_num].bridge_name, bridge_name, bridge_name_length + 1);

	MESA_list_init_head(&g_stream_bridge_manage[g_stream_bridge_actual_num].sync_callback_fun_list);

	g_stream_bridge_actual_num++;
	
	return *bridge_id;
}


void *stream_bridge_create_per_stream(int mem_used_type, int thread_num)
{
	stream_bridge_item_t *stream_bridge_array;

	if(0 == g_stream_bridge_actual_num){
		return NULL;
	}

	stream_bridge_array = (stream_bridge_item_t *)sapp_mem_malloc((sapp_mem_type_t)mem_used_type, thread_num, sizeof(stream_bridge_item_t) * g_stream_bridge_actual_num);
	memset(stream_bridge_array, 0, sizeof(stream_bridge_item_t) * g_stream_bridge_actual_num);

	return (void *)stream_bridge_array;
}

void stream_bridge_destroy_per_stream(int mem_used_type, const struct streaminfo *stream, void *pbridge)
{
	int i;
	stream_bridge_item_t *bridge_array;
	
	if(NULL == pbridge){
		return;
	}

	bridge_array = (stream_bridge_item_t *)(pbridge);

	for(i = 0; i < 	g_stream_bridge_actual_num; i++){
		if(bridge_array[i].valid_flag != 0){
			sapp_global_val->mthread_volatile[stream->threadnum]->sys_stat.count_bridge_in_use[i]--;
		}	
		if((g_stream_bridge_manage[i].async_data_free_cb) && (bridge_array[i].value != 0)){
			g_stream_bridge_manage[i].async_data_free_cb(stream, i, (void *)(bridge_array[i].value));
		}
	}

	sapp_mem_free((sapp_mem_type_t)mem_used_type, stream->threadnum, pbridge);

	return;
}


int stream_bridge_build(const char *bridge_name, const char *rw_mode)
{
	int bridge_id;

	if(strnlen(bridge_name, NAME_MAX+1) >= NAME_MAX){
		sapp_runtime_log(RLOG_LV_FATAL, "stream_bridge_build() error, bridge name too long:%s", bridge_name);
		errno = EINVAL ;
		return -1;
	}

	bridge_id = stream_bridge_name_to_id(bridge_name);

	if(bridge_id < 0){
		if((strncasecmp(rw_mode, "r", 1) == 0) && (strnlen(rw_mode, 2) == 1)){
			return -1;
		}else if((strncasecmp(rw_mode, "w", 1) == 0) || (strncasecmp(rw_mode, "rw", 2) == 0)){
			if(sapp_global_val->individual_volatile->current_state >= SAPP_STATE_PROCESSING){
				sapp_runtime_log(RLOG_LV_FATAL, "stream_bridge_build() error, can't call use write mode in processing state!");
				return -1;
			}
			bridge_id = stream_bridege_create_new_bridge(bridge_name);
		}else{
			sapp_runtime_log(RLOG_LV_FATAL, "stream_bridge_build() error, unknown mode:%s", rw_mode);
			return -1;
		}
	}

	return bridge_id;
}


int stream_bridge_register_data_sync_cb(int bridge_id, stream_bridge_sync_cb_t *cb_fun)
{
	MESA_list_t *new_list_node;
	
	if((bridge_id < 0) || (bridge_id >= STREAM_BRIDGE_MAX_NUM) || (g_stream_bridge_manage[bridge_id].magic_num != STREAM_BRIDGE_MAGIC_SUCC)){
		errno = EINVAL ;
		return -1;
	}

	new_list_node = (struct MESA_list *)sapp_mem_calloc(SAPP_MEM_FIX_GLOBAL_STREAM, -1, sizeof(struct MESA_list));
	new_list_node->quiddity = cb_fun;
	MESA_list_add(&g_stream_bridge_manage[bridge_id].sync_callback_fun_list, new_list_node);

	return 0;
}

int stream_bridge_register_data_free_cb(int bridge_id, stream_bridge_free_cb_t *cb_fun)
{
	if((bridge_id < 0) || (bridge_id >= STREAM_BRIDGE_MAX_NUM) || (g_stream_bridge_manage[bridge_id].magic_num != STREAM_BRIDGE_MAGIC_SUCC)){
		errno = EINVAL ;
		return -1;
	}

	g_stream_bridge_manage[bridge_id].async_data_free_cb = cb_fun;

	return 0;
}


int stream_bridge_async_data_put(const struct streaminfo *stream, int bridge_id, void *data)
{
	stream_bridge_item_t *bridge_item_array;
	struct streaminfo_private *stream_pr;

	if((bridge_id < 0) || (bridge_id >= STREAM_BRIDGE_MAX_NUM) || (g_stream_bridge_manage[bridge_id].magic_num != STREAM_BRIDGE_MAGIC_SUCC)){
		errno = EINVAL ;
		return -1;
	}

	stream_pr = (struct streaminfo_private *)stream;
	bridge_item_array = (stream_bridge_item_t *)stream_pr->stream_bridge;

	bridge_item_array[bridge_id].value = (long long)data;
	if(0 == bridge_item_array[bridge_id].valid_flag){
		sapp_global_val->mthread_volatile[stream->threadnum]->sys_stat.count_bridge_in_use[bridge_id]++;
	}
	bridge_item_array[bridge_id].valid_flag = 1;

	return 0;
}

void *stream_bridge_async_data_get(const struct streaminfo *stream, int bridge_id)
{
	void *result;
	stream_bridge_item_t *bridge_item_array;
	struct streaminfo_private *stream_pr;

	if((bridge_id < 0) || (bridge_id >= STREAM_BRIDGE_MAX_NUM) || (g_stream_bridge_manage[bridge_id].magic_num != STREAM_BRIDGE_MAGIC_SUCC)){
		errno = EINVAL ;
		return NULL;
	}

	stream_pr = (struct streaminfo_private *)stream;
	bridge_item_array = (stream_bridge_item_t *)stream_pr->stream_bridge;

	result = (void *)bridge_item_array[bridge_id].value;
	if(NULL == result){
		if(0 == bridge_item_array[bridge_id].valid_flag){
			errno = ENODATA;	
		}
	}

	return result;

}


int stream_bridge_sync_data_put(const struct streaminfo *stream, int bridge_id, void *data)
{
	stream_bridge_sync_cb_t *sync_cb_fun;
	MESA_list_t *list_node;
	int callback_num = 0;

	if((bridge_id < 0) || (bridge_id >= STREAM_BRIDGE_MAX_NUM) || (g_stream_bridge_manage[bridge_id].magic_num != STREAM_BRIDGE_MAGIC_SUCC)){
		errno = EINVAL ;
		return -1;
	}

	if(MESA_list_is_empty(&g_stream_bridge_manage[bridge_id].sync_callback_fun_list)){
		return 0;
	}

	list_node = g_stream_bridge_manage[bridge_id].sync_callback_fun_list.nextele;
	while(list_node != &g_stream_bridge_manage[bridge_id].sync_callback_fun_list){
		sync_cb_fun = (stream_bridge_sync_cb_t *)list_node->quiddity;
		sync_cb_fun(stream, bridge_id, data);
		list_node = list_node->nextele;
		callback_num++;
	}

	return callback_num;

}


int stream_bridge_init(void)
{
	g_stream_bridge_name2id_htable = stream_bridge_name2id_htable_create();
	assert(g_stream_bridge_name2id_htable);

	return 0;
}

void stream_bridge_destroy(void)
{
	int bridge_id;
	MESA_list_t *list_node, *next_node;
	MESA_htable_destroy(g_stream_bridge_name2id_htable, NULL);

	for(bridge_id = 0; bridge_id < g_stream_bridge_actual_num; bridge_id++){
		list_node = g_stream_bridge_manage[bridge_id].sync_callback_fun_list.nextele;
		while(0 == MESA_list_is_empty(&g_stream_bridge_manage[bridge_id].sync_callback_fun_list)){
			next_node = list_node->nextele;
			MESA_list_del(&g_stream_bridge_manage[bridge_id].sync_callback_fun_list, list_node);
			sapp_mem_free(SAPP_MEM_FIX_GLOBAL_STREAM, -1, (void *)list_node);
			list_node = next_node;
		}
	}

	g_stream_bridge_actual_num = 0;
	memset(g_stream_bridge_manage, 0, sizeof(g_stream_bridge_manage));	
	g_stream_bridge_name2id_htable = NULL;
}


#ifdef __cplusplus
}
#endif


