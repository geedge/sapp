#include "sapp_api.h"
#include "sapp_declaration.h"
#include "sapp_private_api.h"

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
	g_plug_global_entry[this_entry_id].plug_name =  sapp_strdup(plug_name);
	g_plug_global_entry[this_entry_id].plug_entry_name =  sapp_strdup(plug_entry_name);

	g_plug_global_entry_index++;
	
	return this_entry_id;
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

	/* key是字符串, MHO_CBFUN_KEY_COMPARE, MHO_CBFUN_KEY_TO_INDEX使用htable内置的默认函数即�?*/

	/* 此hash表永不超�? 永不淘汰, 可以不注册free callback */
	//MESA_htable_set_opt(htable, MHO_CBFUN_DATA_FREE,  NULL, sizeof(void *));	
	
	ret = MESA_htable_mature(htable);
	
	return htable;
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

	/* 此hash表永不超�? 永不淘汰, 可以不注册free callback */
	//MESA_htable_set_opt(htable, MHO_CBFUN_DATA_FREE,  NULL, sizeof(void *));	
	
	ret = MESA_htable_mature(htable);
	
	return htable;
}


static unsigned int plug_manage_key_to_index_cb(const MESA_htable_handle table, const uchar * key, unsigned int size)
{
	const struct plug_manage_key_t *mg_key = (struct plug_manage_key_t *)key;	
	unsigned int hash_index;

	hash_index = BKDR_hash_algo(table, mg_key->plug_name, strlen(mg_key->plug_name));
	hash_index += BKDR_hash_algo(table, mg_key->plug_entry_type, strlen(mg_key->plug_entry_type));

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

	new_mg_key = (struct plug_manage_key_t *)sapp_mem_alloc(sizeof(struct plug_manage_key_t));
	new_mg_key->plug_name = sapp_strdup(raw_mg_key->plug_name);
	new_mg_key->plug_entry_type = sapp_strdup(raw_mg_key->plug_entry_type);

	return (uchar *)new_mg_key;
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

	/* 此hash表永不超�? 永不淘汰, 可以不注册free callback */
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

	plug_info = (struct plug_uniq_t *)malloc(sizeof(struct plug_uniq_t));
	plug_info->plug_path = strdup(plug_path);
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

int plugin_manage_init(void)
{
	g_plug_necessary_htable = create_plug_necessary_htable();
	assert(g_plug_necessary_htable != NULL);
	
	g_plug_uniq_htable = create_plug_uniq_htable();
	assert(g_plug_uniq_htable != NULL);

	g_plug_manage_htable = create_plug_manage_htable();
	assert(g_plug_manage_htable != NULL);
	
	plugin_parse_necessary_conf();

	/* index 0保留, 全为内置插件, 如 udp_teredo_identify_entry(), gdev_keepalive_udp_entry()等等
       或者是暂不支持entry_id, 而直接调用  stream_register_xxx系列函数注册的插件.
	*/
	g_plug_global_entry[0].entry_id = 0;
	g_plug_global_entry[0].plug_name = sapp_strdup("inner_plug");
	g_plug_global_entry[0].plug_entry_name = sapp_strdup("inner_entry");
	g_plug_global_entry_index++;

	return 0;
}


#ifdef __cplusplus
}
#endif


