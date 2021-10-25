#include "sapp_api.h"
#include "sapp_declaration.h"
#include "sapp_private_api.h"
#include "field_stat2.h"

/*
    sapp挂载插件失败后，仅写错误日志，然后继续加载下一个插件，
	即便所有插件都加载失败，仍然会处理流量，空跑�?	有时候必要的插件如果不加载，sapp运行已无意义，应该退出，这样其他监控程序可以告警�?	而仅写一条错误日志，不方便通过第三方监测程序发现问题�?
	sapp新增配置文件:./etc/necessary_plug_list.conf, 加载插件失败是否退出，根据项目需求灵活选择�?*/

#ifdef __cplusplus
extern "C" {
#endif

/*
   key : plug path;
   data: fake data pointer, non-null;	
*/
static MESA_htable_handle g_plug_necessary_htable;


struct plug_uniq_t{
	const char *plug_path;
	int is_necessary;
	int plug_id; /* 只有protocol解析层才有�? 其他�?1 */
};

/*
   key : plug name;
   data: struct plug_uniq_t
*/
static MESA_htable_handle g_plug_uniq_htable;


struct plug_manage_key_t{
	const char *plug_name;
	const char *plug_entry_type;
};

typedef struct{
	time_t init_time;
	int init_state; /* 0: error; 1: succ */
	long long time_spent_in_us;
	const char *plug_path;
	const char *plug_name;
}plugin_load_state_t;


static plugin_load_state_t g_plugin_load_state[SAPP_MAX_PLUG_ENTRY_NUM];
static int plugin_load_state_num = 0;
static void *g_plug_load_stat_fs2_handle;
static int g_plug_load_stat_fs2_column_id;


/* 
	根据插件的名称和入口函数名称, 找到入口函数在内存中的地址.
   key : plug name, and plug entry name(TCP, UDP, HTTP, etc),
   data: entry function addr; 
*/
static MESA_htable_handle g_plug_manage_htable;


plug_global_entry_t g_plug_global_entry[SAPP_MAX_PLUG_ENTRY_NUM];
int g_plug_global_entry_index;
/*
	TODO1:
		插件加载失败是否退�? 取决于g_plug_uniq_htable中的necessary是否设置;

	TODO2:
		插件获取自己的pme, 传入streaminfo和plugname, entry_type_string,

		先从g_plug_manage_htable找到这个插件的entry函数入口地址, 这是全局�? 来自dlopen插件.so, 不会�?

		然后在当前streaminfo的三个pdetail_private里找插件列表, 参�? MESA_get_stream_plug_pme()
		
		其中有些函数可能是解析层函数入口, 可以通过 g_protocol_plug_info 比较得知;
		如果不是解析层函�? 等同于现在的MESA_get_stream_plug_pme, 
		
		如果是解析层函数, 需要继续递归查找挂载到当前解析层插件的业务插件列�? 
		先找到解析层的pme, 但是这个私有结构都是解析插件自定义的, 
		比如http_stream,  在http_stream里还有个指针, 才是业务插件函数调用链的pme, 
		只有找到了这个pme, 才能转换�?stSessionFunInfo 结构, 然后通过比较appentry是否相同, 最后取出业务插件的pme.

		但是, 解析层插件暴露给sapp平台的pme, 和业务插件对解析层的pme不是一个变�? 如何能找到解析层的业务插件pme指针???
		而且, 一个tcp流里可能有多个http session, 每个http session又对应了一个业务插件的pme调用�? 且只有解析层插件自己知道这个结构, 
		仅在sapp内部, 目前是不可能找到解析层上挂载的每个业务层插件pme�?!!	
*/


int plug_mange_get_entry_id(const char *plug_name, const char *plug_entry_name)
{
	int this_entry_id;
	
	if(g_plug_global_entry_index >= SAPP_MAX_PLUG_ENTRY_NUM){
		sapp_runtime_log(RLOG_LV_FATAL, "plug entry number overflow! no valid id for %s->%s\n", plug_name, plug_entry_name);
		return -1;
	}
	this_entry_id = g_plug_global_entry_index;
	g_plug_global_entry[this_entry_id].entry_id = this_entry_id;
	g_plug_global_entry[this_entry_id].plug_name =  (char *)sapp_mem_calloc(SAPP_MEM_FIX_PLUG_CTRL, -1, strlen(plug_name)+1);
	strncpy((char *)g_plug_global_entry[this_entry_id].plug_name, plug_name, strlen(plug_name));
	
	g_plug_global_entry[this_entry_id].plug_entry_name =  (char *)sapp_mem_calloc(SAPP_MEM_FIX_PLUG_CTRL, -1, strlen(plug_entry_name)+1);
	strncpy((char *)g_plug_global_entry[this_entry_id].plug_entry_name, plug_entry_name, strlen(plug_entry_name));
	g_plug_global_entry_index++;
	
	return this_entry_id;
}

static void plug_necessary_htable_free_cb(void *data)
{
	//necessary htable没有实际的data, 只有key
	;//do nothing
}

static MESA_htable_handle create_plug_necessary_htable(void)
{
	MESA_htable_handle htable;
	int ret, opt_int;
	
	htable = MESA_htable_born();
	assert(htable != NULL);

	opt_int = 0;
	MESA_htable_set_opt(htable, MHO_THREAD_SAFE, &opt_int, sizeof(int));

	opt_int = 1024 * 128;
	MESA_htable_set_opt(htable, MHO_HASH_SLOT_SIZE, &opt_int, sizeof(int));

	opt_int = 10000;
	MESA_htable_set_opt(htable, MHO_HASH_MAX_ELEMENT_NUM, &opt_int, sizeof(int));

	opt_int = 0;
	MESA_htable_set_opt(htable, MHO_EXPIRE_TIME, &opt_int, sizeof(int));

	opt_int = 0;
	MESA_htable_set_opt(htable, MHO_SCREEN_PRINT_CTRL, &opt_int, sizeof(int));

	opt_int = HASH_ELIMINATE_ALGO_FIFO;
	MESA_htable_set_opt(htable, MHO_ELIMIMINATE_TYPE, &opt_int, sizeof(int));	

	/* key是字符串, MHO_CBFUN_KEY_COMPARE, MHO_CBFUN_KEY_TO_INDEX使用htable内置的默认函�?*/

	MESA_htable_set_opt(htable, MHO_CBFUN_DATA_FREE,  (void *)plug_necessary_htable_free_cb, sizeof(void *));	
	
	ret = MESA_htable_mature(htable);
	
	return htable;
}

static void plug_uniq_htable_free_cb(void *data)
{
	struct plug_uniq_t *plug_info = (struct plug_uniq_t *)data;

	sapp_mem_free(SAPP_MEM_FIX_PLUG_CTRL, -1, (void *)plug_info->plug_path);
	sapp_mem_free(SAPP_MEM_FIX_PLUG_CTRL, -1, (void *)plug_info);
}


static MESA_htable_handle create_plug_uniq_htable(void)
{
	MESA_htable_handle htable;
	int ret, opt_int;
	
	htable = MESA_htable_born();
	assert(htable != NULL);

	opt_int = 0;
	MESA_htable_set_opt(htable, MHO_THREAD_SAFE, &opt_int, sizeof(int));

	opt_int = 1024 * 128;
	MESA_htable_set_opt(htable, MHO_HASH_SLOT_SIZE, &opt_int, sizeof(int));

	opt_int = 10000;
	MESA_htable_set_opt(htable, MHO_HASH_MAX_ELEMENT_NUM, &opt_int, sizeof(int));

	opt_int = 0;
	MESA_htable_set_opt(htable, MHO_EXPIRE_TIME, &opt_int, sizeof(int));

	opt_int = 0;
	MESA_htable_set_opt(htable, MHO_SCREEN_PRINT_CTRL, &opt_int, sizeof(int));

	opt_int = HASH_ELIMINATE_ALGO_FIFO;
	MESA_htable_set_opt(htable, MHO_ELIMIMINATE_TYPE, &opt_int, sizeof(int));	

	/* key是字符串, MHO_CBFUN_KEY_COMPARE, MHO_CBFUN_KEY_TO_INDEX使用htable内置的默认函数即�?*/

	MESA_htable_set_opt(htable, MHO_CBFUN_DATA_FREE,  (void *)plug_uniq_htable_free_cb, sizeof(void *));	
	
	ret = MESA_htable_mature(htable);
	
	return htable;
}


static unsigned int plug_manage_key_to_index_cb(const MESA_htable_handle table, const uchar * key, unsigned int size)
{
	const struct plug_manage_key_t *mg_key = (struct plug_manage_key_t *)key;	
	unsigned int hash_index;

	hash_index = BKDR_hash_algo(table, (unsigned char*)mg_key->plug_name, strlen(mg_key->plug_name));
	hash_index += BKDR_hash_algo(table, (unsigned char*)mg_key->plug_entry_type, strlen(mg_key->plug_entry_type));

	return hash_index;
}

static int plug_manage_key_cmp_cb(const uchar * key1, uint size1, const uchar * key2, uint size2)
{
	if(size1 != size2){
		return -1;
	}

	const struct plug_manage_key_t *mg_key1 = (struct plug_manage_key_t *)key1;	
	const struct plug_manage_key_t *mg_key2 = (struct plug_manage_key_t *)key2;	

	if(strcasecmp(mg_key1->plug_name, mg_key2->plug_name) != 0){
		return -1;
	}

	if(strcasecmp(mg_key1->plug_entry_type, mg_key2->plug_entry_type) != 0){
		return -1;
	}

	return 0;
}


static uchar * plug_manage_key_dup_cb(const uchar *key, uint key_size)
{
	struct plug_manage_key_t *new_mg_key; 
	const struct plug_manage_key_t *raw_mg_key = (struct plug_manage_key_t *)key;

	new_mg_key = (struct plug_manage_key_t *)sapp_mem_calloc(SAPP_MEM_FIX_PLUG_CTRL, MEM_STAT_GLOBAL_THREAD_ID,sizeof(struct plug_manage_key_t));
	new_mg_key->plug_name = (char *)sapp_mem_calloc(SAPP_MEM_FIX_PLUG_CTRL, MEM_STAT_GLOBAL_THREAD_ID, strlen(raw_mg_key->plug_name)+1);
	strncpy((char *)new_mg_key->plug_name, raw_mg_key->plug_name, strlen(raw_mg_key->plug_name));
	
	new_mg_key->plug_entry_type = (char *)sapp_mem_calloc(SAPP_MEM_FIX_PLUG_CTRL, MEM_STAT_GLOBAL_THREAD_ID, strlen(raw_mg_key->plug_entry_type)+1);
	strncpy((char *)new_mg_key->plug_entry_type, raw_mg_key->plug_entry_type, strlen(raw_mg_key->plug_entry_type));

	return (uchar *)new_mg_key;
}


static void plug_manage_key_free_cb(uchar *key, uint key_size)
{
	struct plug_manage_key_t *raw_mg_key = (struct plug_manage_key_t *)key;

	sapp_mem_free(SAPP_MEM_FIX_PLUG_CTRL, MEM_STAT_GLOBAL_THREAD_ID, (void *)raw_mg_key->plug_name);
	sapp_mem_free(SAPP_MEM_FIX_PLUG_CTRL, MEM_STAT_GLOBAL_THREAD_ID, (void *)raw_mg_key->plug_entry_type);
	sapp_mem_free(SAPP_MEM_FIX_PLUG_CTRL, MEM_STAT_GLOBAL_THREAD_ID, (void *)raw_mg_key);
}


static MESA_htable_handle create_plug_manage_htable(void)
{
	MESA_htable_handle htable;
	int ret, opt_int;
	
	htable = MESA_htable_born();
	assert(htable != NULL);

	opt_int = 0;
	MESA_htable_set_opt(htable, MHO_THREAD_SAFE, &opt_int, sizeof(int));

	opt_int = 1024 * 128;
	MESA_htable_set_opt(htable, MHO_HASH_SLOT_SIZE, &opt_int, sizeof(int));

	opt_int = 10000;
	MESA_htable_set_opt(htable, MHO_HASH_MAX_ELEMENT_NUM, &opt_int, sizeof(int));

	opt_int = 0;
	MESA_htable_set_opt(htable, MHO_EXPIRE_TIME, &opt_int, sizeof(int));

	opt_int = 0;
	MESA_htable_set_opt(htable, MHO_SCREEN_PRINT_CTRL, &opt_int, sizeof(int));

	opt_int = HASH_ELIMINATE_ALGO_FIFO;
	MESA_htable_set_opt(htable, MHO_ELIMIMINATE_TYPE, &opt_int, sizeof(int));	

	MESA_htable_set_opt(htable, MHO_CBFUN_KEY_TO_INDEX,  (void *)&plug_manage_key_to_index_cb, sizeof(void *));
	
	MESA_htable_set_opt(htable, MHO_CBFUN_KEY_COMPARE, (void *)&plug_manage_key_cmp_cb, sizeof(void *));		

	MESA_htable_set_opt(htable, MHO_CBFUN_COMPLEX_KEY_DUP,  (void *)&plug_manage_key_dup_cb, sizeof(void *));	

	MESA_htable_set_opt(htable, MHO_CBFUN_COMPLEX_KEY_FREE, (void *)&plug_manage_key_free_cb, sizeof(void *));

	/* 注意: plug_manage的data是dlopen的函数地址, 不能注册free callback */
	//MESA_htable_set_opt(htable, MHO_CBFUN_DATA_FREE,  NULL, sizeof(void *));	
	//MESA_htable_set_opt(htable, MHO_CBFUN_COMPLEX_KEY_FREE,  (void *)&ipv4_frag_key_free, sizeof(void *));	
	
	ret = MESA_htable_mature(htable);
	
	return htable;
}


int plugin_is_necessary(const char *plug_path)
{
	if(MESA_htable_search(g_plug_necessary_htable, (unsigned char *)plug_path, strlen(plug_path)) != NULL){
		return 1;
	}

	return 0;
}

/* 
	加载一个新的插�? 全局名称不能重复.
*/
int plugin_load_new_plug(const char *plug_name, const char *plug_path)
{
	struct plug_uniq_t *plug_info;

	plug_info = (struct plug_uniq_t *)MESA_htable_search(g_plug_uniq_htable, (unsigned char *)plug_name, strlen(plug_name));
	if(plug_info != NULL){
		sapp_log(30, 1, 1, "plugin %s->[PLUGNAME]=%s has duplicate name with %s->[PLUGNAME]=%s!", plug_path, plug_name, plug_info->plug_path, plug_name);
		return -1;
	}

	plug_info = (struct plug_uniq_t *)sapp_mem_calloc(SAPP_MEM_FIX_PLUG_CTRL, -1, sizeof(struct plug_uniq_t));
	plug_info->plug_path = (char *)sapp_mem_calloc(SAPP_MEM_FIX_PLUG_CTRL, -1, strlen(plug_path)+1);
	strncpy((char *)plug_info->plug_path, plug_path, strlen(plug_path));
	plug_info->is_necessary = plugin_is_necessary(plug_path);

	MESA_htable_add(g_plug_uniq_htable, (unsigned char *)plug_name, strlen(plug_name), plug_info);

	return 0;
}


/* 
	加载一个新的插件的entry, 一个插件可以同时有多个不同层的entry, 如TCP, UDP, HTTP, DNS�?..
*/
int plugin_load_new_plug_entry(const char *plug_name, const char *plug_entry_type, void *entry_addr)
{
	struct plug_manage_key_t mg_key = {};
	int ret;

	mg_key.plug_name = plug_name;
	mg_key.plug_entry_type = plug_entry_type;
	
	ret = MESA_htable_add(g_plug_manage_htable, (const uchar * )&mg_key, sizeof(struct plug_manage_key_t), entry_addr);

	assert(ret >= 0);

	return 0;
}

/*
	根据插件名称和入口函数类�? 获取入口函数地址.
*/
void *plugin_get_plug_entry(const char *plug_name, const char *plug_entry_type)
{
	struct plug_manage_key_t mg_key = {};
	int ret;
	void *plug_entry_addr;

	mg_key.plug_name = plug_name;
	mg_key.plug_entry_type = plug_entry_type;
	
	plug_entry_addr = MESA_htable_search(g_plug_manage_htable, (const uchar * )&mg_key, sizeof(struct plug_manage_key_t));

	return plug_entry_addr;
}


/*
	文件内容�?/plug/conflist.inf, 但是无段落标�?
*/
static int plugin_parse_necessary_conf(void)
{
	FILE *fp;
	char line_buf[1024];

	fp = fopen(ABBR_NECESSARY_PLUG_CONF_FILE, "r");
	if(NULL == fp){
		/* 没有此文�? 或空文件都不是错�? 表示没有必需的插�?*/
		return 0;
	}

	while(fgets(line_buf, 1024, fp)){
		if('#' == line_buf[0] || ' ' == line_buf[0] || '\r' == line_buf[0] || '\n' == line_buf[0]){
			continue;
		}	
		del_last_rn(line_buf, 1024);

		MESA_htable_add(g_plug_necessary_htable, (unsigned char *)line_buf, strlen(line_buf), (void *)0x12345678);
	}

	fclose(fp);
	return 0;
}



/*
	此函数有可能在不同阶段被重复调用, 先查找有没有此插件的历史记录.
*/
void plugin_load_state_update(int init_state, long long time_spent_in_us, const char *plug_path, const char *plug_name)
{
	int i, index, bingo;

	if(plugin_load_state_num >= SAPP_MAX_PLUG_ENTRY_NUM){
		MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"plugin_load_state_update() error, plug number overload, max support:%d", SAPP_MAX_PLUG_ENTRY_NUM);	
		return;
	}

	bingo = 0;
	index = -1;
	for(i = 0; i < SAPP_MAX_PLUG_ENTRY_NUM; i++){
		if((g_plugin_load_state[i].plug_path != NULL) && 
		  (strncmp(g_plugin_load_state[i].plug_path, plug_path, strlen(plug_path)) == 0)){
			index = i;
			bingo = 1;
			break;
		}
	}

	if(0 == bingo){
		/* not found history, is new plug */
		index = plugin_load_state_num;
		plugin_load_state_num++;
	}

	g_plugin_load_state[index].init_time = time(NULL);

	if(init_state < 0){
		g_plugin_load_state[index].init_state = 0;
		g_plugin_load_state[index].time_spent_in_us = 0; /* 初始化失败记为0 */
	}else{
		g_plugin_load_state[index].init_state = 1;
		g_plugin_load_state[index].time_spent_in_us = time_spent_in_us;
	}
	if(0 == bingo){
		g_plugin_load_state[index].plug_path = sapp_strdup(plug_path);
		if(plug_name){
			g_plugin_load_state[index].plug_name = sapp_strdup(plug_name);
		}
	}
}

/* 对于qsort来说, item1,item2是每个数组成员的地址, 对于本例来说, 即指针的指针, 所以是plugin_load_state_t ** */
static int qsort_compare_time_spent_cb(const void *item1, const void *item2)
{
	const plugin_load_state_t **load_state1 = (const plugin_load_state_t **)item1;
	const plugin_load_state_t **load_state2 = (const plugin_load_state_t **)item2;
	
	return (int)((*load_state1)->time_spent_in_us - (*load_state2)->time_spent_in_us);
}


int sapp_plugin_load_state_fs2_init(void)
{
	int fs2_opt;
	unsigned short fs_server_port;
	
	g_plug_load_stat_fs2_handle = FS_create_handle();

	/*
		prometheus相关的配置, 由  	   sapp_fs2_init() 初始化.
	*/

	fs2_opt = sapp_global_val->config.profiling.log.interval;
	FS_set_para(g_plug_load_stat_fs2_handle, STAT_CYCLE, &fs2_opt, sizeof(int));	

	fs2_opt = 1; /* 1:Rewrite ,2: Append.  */
	FS_set_para(g_plug_load_stat_fs2_handle, PRINT_MODE, &fs2_opt, sizeof(int));

	fs2_opt = 1;
	FS_set_para(g_plug_load_stat_fs2_handle, PRINT_TRIGGER, &fs2_opt, sizeof(int));

	if(sapp_global_val->config.profiling.log.local.enabled){
		FS_set_para(g_plug_load_stat_fs2_handle, OUTPUT_DEVICE, "./fs2_plug_stat.log", strlen("./fs2_plug_stat.log") + 1); 
	}
	
	FS_set_para(g_plug_load_stat_fs2_handle, APP_NAME, "plug_load", strlen("plug_load")+1);

	if(sapp_global_val->config.profiling.log.remote.enabled){
		FS_set_para(g_plug_load_stat_fs2_handle, STATS_SERVER_IP, (void *)sapp_global_val->config.profiling.log.remote.server_ip, strlen(sapp_global_val->config.profiling.log.remote.server_ip)+1);
		fs_server_port = (unsigned short)sapp_global_val->config.profiling.log.remote.server_port;
		FS_set_para(g_plug_load_stat_fs2_handle, STATS_SERVER_PORT, &fs_server_port, sizeof(short));
	}

	if(sapp_global_val->config.profiling.log.prometheus.enabled){
		fs2_opt = 1;
		FS_set_para(g_plug_load_stat_fs2_handle, OUTPUT_PROMETHEUS, &fs2_opt, sizeof(int));
	}

	/* 先注册列, 初始化后固定不变, 行以plug_name为单位动态注册, 动态增加 */
	g_plug_load_stat_fs2_column_id = FS_register(g_plug_load_stat_fs2_handle, FS_STYLE_COLUMN, FS_CALC_CURRENT, "status");

	FS_start(g_plug_load_stat_fs2_handle);

	return 0;
}

/* 
	field stat注册名称时不允许用  "|:\n\r.\t<>[]#!@", 所以常见的字符里, 只能改成"_".
*/
static void sapp_plug_modify_char(char *str, int raw_char, int new_char)
{
	char *ptr;

	while(ptr = strchr(str, raw_char)){
		*ptr = (char)new_char;
	}
}


int sapp_plug_stat_dynamic_register_fs2_line(const char *plug_path, long load_stats)
{
	char valid_fs2_plug_path[PATH_MAX];

	strncpy(valid_fs2_plug_path, plug_path, PATH_MAX);
	sapp_plug_modify_char(valid_fs2_plug_path, '.', '_');
	
	/* 此处 fs2_line_id 仅用一次, 用临时变量就行了 */
	int fs2_line_id = FS_register(g_plug_load_stat_fs2_handle, FS_STYLE_LINE, FS_CALC_CURRENT, valid_fs2_plug_path);

	FS_operate(g_plug_load_stat_fs2_handle, fs2_line_id, g_plug_load_stat_fs2_column_id, FS_OP_SET, load_stats);

	return 0;
}


void sapp_plugin_load_state_output(void)
{
	int i;
	plugin_load_state_t *ptr_plugin_load_state[128] = {};
	char time_str[64];
	FILE *fp;

	fp = fopen(ABBR_LOAD_PLUG_STAT_LOG_DATA_FILE, "w+");
	if(NULL == fp){
		return;
	}

	for(i = 0; i < plugin_load_state_num; i++){
		ptr_plugin_load_state[i] = &g_plugin_load_state[i];
	}

	qsort(ptr_plugin_load_state, plugin_load_state_num, sizeof(void *), qsort_compare_time_spent_cb);

	fprintf(fp, "-----------------------------------------------------------------------------------------------\n");
	fprintf(fp, "sapp load plugins statistics:\n");
	fprintf(fp, "%20s %5s %13s %6s\n", "start_time", "state", "time_spent_us", "plugin_path");

	fprintf(fp, "-----------------------------------------------------------------------------------------------\n");
	for(i = 0; i < plugin_load_state_num; i++){
		timet_to_str(ptr_plugin_load_state[i]->init_time, time_str, sizeof(time_str));
		fprintf(fp, "%20s %5s %13lld %6s\n", time_str, 
				(ptr_plugin_load_state[i]->init_state < 0) ? "\033[1;31;40mFAIL\033[0m":"\033[32mSUCC\033[0m", 
				ptr_plugin_load_state[i]->time_spent_in_us, 
				ptr_plugin_load_state[i]->plug_path);	
		sapp_plug_stat_dynamic_register_fs2_line(g_plugin_load_state[i].plug_path, g_plugin_load_state[i].init_state);
	}	
	fprintf(fp, "-----------------------------------------------------------------------------------------------\n");

	if(fp){
		fclose(fp);
	}
}


int plugin_manage_init(void)
{
	g_plug_necessary_htable = create_plug_necessary_htable();
	assert(g_plug_necessary_htable != NULL);
	
	g_plug_uniq_htable = create_plug_uniq_htable();
	assert(g_plug_uniq_htable != NULL);

	g_plug_manage_htable = create_plug_manage_htable();
	assert(g_plug_manage_htable != NULL);
	
	plugin_parse_necessary_conf();

	/* index 0保留, 全为内置插件, �?udp_teredo_identify_entry(), gdev_keepalive_udp_entry()等等
       或者是暂不支持entry_id, 而直接调�? stream_register_xxx系列函数注册的插�?
	*/
	g_plug_global_entry[0].entry_id = 0;
	g_plug_global_entry[0].plug_name = sapp_strdup("inner_plug");
	g_plug_global_entry[0].plug_entry_name = sapp_strdup("inner_entry");
	g_plug_global_entry_index++;

	sapp_plugin_load_state_fs2_init();

	return 0;
}

void plugin_manage_destroy(void)
{
	int i;
	
	MESA_htable_destroy(g_plug_necessary_htable, NULL);
	g_plug_necessary_htable = NULL;
	
	MESA_htable_destroy(g_plug_uniq_htable, NULL);
	g_plug_uniq_htable = NULL;
	
	MESA_htable_destroy(g_plug_manage_htable, NULL);
	g_plug_manage_htable = NULL;

	for(i = 0; i < g_plug_global_entry_index; i++){
		sapp_mem_free(SAPP_MEM_FIX_PLUG_CTRL, -1, (void *)g_plug_global_entry[i].plug_name);
		sapp_mem_free(SAPP_MEM_FIX_PLUG_CTRL, -1, (void *)g_plug_global_entry[i].plug_entry_name);
	}
	memset(g_plug_global_entry, 0, sizeof(g_plug_global_entry));
	g_plug_global_entry_index = 0;

	for(i = 0; i < plugin_load_state_num; i++){
		SAPP_GLOBAL_FREE(g_plugin_load_state[i].plug_path);
		SAPP_GLOBAL_FREE(g_plugin_load_state[i].plug_name);
	}
	memset(g_plugin_load_state, 0, sizeof(g_plugin_load_state));
	plugin_load_state_num = 0;

	if(g_plug_load_stat_fs2_handle){
		FS_stop(&g_plug_load_stat_fs2_handle);
	}	
}

#ifdef __cplusplus
}
#endif


