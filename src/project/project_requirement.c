#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"
#include "sapp_declaration.h"
#include "MESA_list.h"

//extern int g_packet_io_thread_num;
extern int project_req_terminal_tag_init(void);
extern int raw_ip_frag_list_v4_init(void);
extern int raw_ip_frag_list_v6_init(void);
extern void del_last_rn(char *data, int max_len);
extern int tcp_flow_stat_init(void);
extern int G_UDP_FLOW_STAT_PROJECT_ID;

enum pro_type_list{
	PROGECT_REQ_VALUE_TYPE_SIMPLE_CHAR = 0,
	PROGECT_REQ_VALUE_TYPE_SIMPLE_SHORT,
	PROGECT_REQ_VALUE_TYPE_SIMPLE_INT,
	PROGECT_REQ_VALUE_TYPE_SIMPLE_LONG,
	PROGECT_REQ_VALUE_TYPE_STRUCT,
	PROGECT_REQ_VALUE_TYPE_MAX,
};

struct pro_req_type{
	int type_id;
	char *type_str;
};


typedef struct project_req_m{
	int project_req_id;
	char project_req_name[PROJECT_REQ_NAME_MAX_LEN];
	project_req_free_t *free_cb;
	int project_req_type;
}project_req_manage_t;

struct project_req_info{
	long long value;
	char valid_flag; /* 用于识别初始状态值为0, 和外部调用者设置了0, 两种值相同但不同的状态 */
}__attribute__((packed, aligned(1)));
typedef struct project_req_info project_req_info_t;

static project_req_manage_t G_PROJECT_REQ_MANAGE[PROJECT_REQ_MAX_PLUG_NUM];
static void *G_PROJECT_NAME_HASH = NULL;

static int G_PROJECT_PLUG_NUM = 0;

static struct pro_req_type G_PROJECT_TYPE[PROGECT_REQ_VALUE_TYPE_MAX] = 
{
	{PROGECT_REQ_VALUE_TYPE_SIMPLE_CHAR,	(char *)"char"},
	{PROGECT_REQ_VALUE_TYPE_SIMPLE_SHORT,	(char *)"short"},
	{PROGECT_REQ_VALUE_TYPE_SIMPLE_INT,		(char *)"int"},
	{PROGECT_REQ_VALUE_TYPE_SIMPLE_LONG,	(char *)"long"},
	{PROGECT_REQ_VALUE_TYPE_STRUCT,			(char *)"struct"},
};

static int project_req_str_to_type_id(const char *project_req_val_type)
{
	int i, pro_req_type = -1;

	for(i = 0; i < PROGECT_REQ_VALUE_TYPE_MAX; i++){
		if(strncasecmp(project_req_val_type, G_PROJECT_TYPE[i].type_str, strlen(G_PROJECT_TYPE[i].type_str)) == 0){
			pro_req_type  = G_PROJECT_TYPE[i].type_id;
		}
	}

	return pro_req_type;
}

const char *project_find_name_by_id(int project_id)
{
	if((project_id < 0) || (project_id >= G_PROJECT_PLUG_NUM)){
		return NULL;
	}

	return G_PROJECT_REQ_MANAGE[project_id].project_req_name;
}

static int __project_find_id_by_name(const char *project_req_name, const char *project_req_val_type)
{
	int i, pro_req_id = -1;
	project_req_manage_t *preq_man = NULL;

	if(NULL == project_req_name || NULL == project_req_val_type){
		return -1;
	}

	if(strlen(project_req_name) >= PROJECT_REQ_NAME_MAX_LEN){
		return -1;
	}

	for(i = 0; i < G_PROJECT_PLUG_NUM; i++){
		if(strncasecmp(project_req_name, G_PROJECT_REQ_MANAGE[i].project_req_name, PROJECT_REQ_NAME_MAX_LEN) == 0){
			preq_man = &G_PROJECT_REQ_MANAGE[i];
			pro_req_id = i;
			break;
		}
	}
	if(NULL == preq_man || -1 == pro_req_id){
		sapp_runtime_log(RLOG_LV_FATAL, "can't found project name:'%s' in %s\n", project_req_name, ABBR_PROJECT_LIST_CONF_FILE);
		return -1;
	}

	return pro_req_id;
}

static int project_platform_register(const char *project_req_name, enum pro_type_list type, project_req_free_t *free_cb)
{
	int pid = G_PROJECT_PLUG_NUM;
	if(sapp_get_current_state() == SAPP_STATE_PROCESSING)
	{
		sapp_runtime_log(30, "project_platform_register (%s) FAIL: SAPP_STATE_PROCESSING state not allow to register", project_req_name);
		return -1;
	}
	if (G_PROJECT_NAME_HASH == NULL || (type >= PROGECT_REQ_VALUE_TYPE_MAX || type < 0))
	{
		sapp_runtime_log(30, "project_platform_register (%s) FAIL: Empty G_PROJECT_NAME_HASH or Invalid pro_type(%d)", project_req_name, type);
		return -1;
	}
	int *project_id = (int *)MESA_htable_search(G_PROJECT_NAME_HASH, project_req_name, strlen(project_req_name));
	if (project_id != NULL)
	{
		sapp_runtime_log(30, "project_platform_register (%s) DUPLICATE, exist project_id %d", project_req_name, *project_id);
		return *project_id;
	}
	else
	{

		if (pid >= PROJECT_REQ_MAX_PLUG_NUM)
		{

			sapp_runtime_log(30, "project_platform_register (%s) FAIL: Project tag number overflow, more than %d", project_req_name, PROJECT_REQ_MAX_PLUG_NUM);
			return -1;
		}
		G_PROJECT_REQ_MANAGE[G_PROJECT_PLUG_NUM].project_req_id = G_PROJECT_PLUG_NUM;
		strncpy(G_PROJECT_REQ_MANAGE[G_PROJECT_PLUG_NUM].project_req_name, project_req_name, PROJECT_REQ_NAME_MAX_LEN);
		G_PROJECT_REQ_MANAGE[G_PROJECT_PLUG_NUM].free_cb = free_cb;
		G_PROJECT_REQ_MANAGE[G_PROJECT_PLUG_NUM].project_req_type = type;
		project_id = (int *)calloc(sizeof(int), 1);
		*project_id = pid;
		MESA_htable_add(G_PROJECT_NAME_HASH, project_req_name, strlen(project_req_name), (const void *)project_id);
		G_PROJECT_PLUG_NUM++;
		sapp_runtime_log(20, "project_platform_register (%s) SUCCEED, project_id return %d", project_req_name, pid);
		return pid;
	}
}

int project_producer_register(const char *project_req_name, const char *project_req_val_type, project_req_free_t *free_cb)
{
	int pro_req_id = -1;

	//pro_req_id = __project_find_id_by_name(project_req_name, project_req_val_type);
	pro_req_id = project_platform_register(project_req_name, project_req_str_to_type_id(project_req_val_type), free_cb);

	if(pro_req_id != -1){
		if((NULL == free_cb )
		&& (PROGECT_REQ_VALUE_TYPE_STRUCT == G_PROJECT_REQ_MANAGE[pro_req_id].project_req_type)){
			sapp_runtime_log(30, "project_producer_register() must implement 'free_cb' with 'struct' type!\n");
			return -1;
		}
		sapp_runtime_log(30, "project_platform_register (\033[32m%s, %s\033[0m) SUCCEED, project_id return \033[32m%d\033[0m!", project_req_name, project_req_val_type, pro_req_id);
		G_PROJECT_REQ_MANAGE[pro_req_id].free_cb = free_cb;//overwrite free_cb with new register operation
	}
	
	return pro_req_id;
}

int project_customer_register(const char *project_req_name, const char *project_req_val_type)
{
	return __project_find_id_by_name(project_req_name, project_req_val_type);
}


#if 0 /* 采用动态注册, 不再需要project_list.conf文件 */
int parse_project_req_conf(void)
{
	char *save_ptr;
	const char *delim = "\t ";
	char line_buf[1024];
	FILE *fp;
	char *preq_name;
	char *preq_type;
	int i, line_num = 1;
	

	fp = fopen(ABBR_PROJECT_LIST_CONF_FILE, "r");
	if(NULL == fp){
		sapp_log(30, ~0, ~0, "Open '%s' error: %s", ABBR_PROJECT_LIST_CONF_FILE, strerror(errno));
		//return -1;
		exit(1);
	}

	while(fgets(line_buf, 1024, fp) != NULL){
		if('#' == line_buf[0] || ' ' == line_buf[0] || '\r' == line_buf[0] || '\n' == line_buf[0]){
			line_num++;
			continue;
		}
		del_last_rn(line_buf, 1024);
		
		preq_name = strtok_r(line_buf, delim, &save_ptr);
		if(NULL == preq_name){
			printf("invalid conf in %s, line %d\n", ABBR_PROJECT_LIST_CONF_FILE, line_num);
			return -1;
		}

		preq_type = strtok_r(NULL, delim, &save_ptr);
		if(NULL == preq_type){
			printf("invalid conf in %s, line %d\n", ABBR_PROJECT_LIST_CONF_FILE, line_num);
			return -1;
		}

		while(strtok_r(NULL, delim, &save_ptr));

		/* search duplicate conf */
		for(i = 0; i < G_PROJECT_PLUG_NUM; i++){
			if(strncasecmp(preq_name, G_PROJECT_REQ_MANAGE[i].project_req_name, PROJECT_REQ_NAME_MAX_LEN) == 0){
				printf("duplicate conf in %s, line %d\n", ABBR_PROJECT_LIST_CONF_FILE, line_num);
				return -1;
			}
		}
	
		G_PROJECT_REQ_MANAGE[G_PROJECT_PLUG_NUM].project_req_id = G_PROJECT_PLUG_NUM;
		strncpy(G_PROJECT_REQ_MANAGE[G_PROJECT_PLUG_NUM].project_req_name, preq_name, PROJECT_REQ_NAME_MAX_LEN);
		G_PROJECT_REQ_MANAGE[G_PROJECT_PLUG_NUM].project_req_type = project_req_str_to_type_id(preq_type);
		if(G_PROJECT_REQ_MANAGE[G_PROJECT_PLUG_NUM].project_req_type < 0){
			printf("invalid conf in %s, line %d\n", ABBR_PROJECT_LIST_CONF_FILE, line_num);
			return -1;
		}
	
		line_num++;
		G_PROJECT_PLUG_NUM++;
	}

	fclose(fp);
	return 0;
}
#endif


static int project_req_conf_is_exist(const char *check_name)
{
	char *save_ptr;
	const char *delim = "\t ";
	char line_buf[1024];
	FILE *fp;
	char *preq_name;
	int line_num = 0;
	int section_is_exist = 0;

	fp = fopen(ABBR_PROJECT_LIST_CONF_FILE, "r");
	if(NULL == fp){
		sapp_log(RLOG_LV_DEBUG, 1, 1, "Open project list config: '%s' error: %s", ABBR_PROJECT_LIST_CONF_FILE, strerror(errno));
		return 0;
	}

	while(fgets(line_buf, 1024, fp) != NULL){
		if('#' == line_buf[0] || ' ' == line_buf[0] || '\r' == line_buf[0] || '\n' == line_buf[0]){
			line_num++;
			continue;
		}
		del_last_rn(line_buf, 1024);
		
		preq_name = strtok_r(line_buf, delim, &save_ptr);
		if(NULL == preq_name){
			sapp_printf("invalid conf in %s, line %d\n", ABBR_PROJECT_LIST_CONF_FILE, line_num);
			sapp_runtime_log(RLOG_LV_INFO, "invalid conf in %s, line %d\n", ABBR_PROJECT_LIST_CONF_FILE, line_num);
			goto fun_exit;
		}

		if(strncasecmp(preq_name, check_name, strlen(preq_name)) == 0){
			section_is_exist = 1;
			goto fun_exit;
		}

		while(strtok_r(NULL, delim, &save_ptr));
		line_num++;
	}

fun_exit:

	fclose(fp);
	return section_is_exist;
}


static int __project_req_add(struct streaminfo *stream, int project_req_id, long long project_req_value, int pro_req_type)
{
	project_req_info_t *pinfo;
	struct streaminfo_private *stream_pr;
	
	if(project_req_id < 0 || project_req_id >= G_PROJECT_PLUG_NUM){
		return -1;
	}

	if(G_PROJECT_REQ_MANAGE[project_req_id].project_req_type != pro_req_type){
		return -1;
	}

	stream_pr = (struct streaminfo_private *)stream;
	pinfo = (project_req_info_t *)(stream_pr->pproject);
	if(NULL == pinfo){
		sapp_runtime_log(RLOG_LV_FATAL, "project add error, id=%d, value is:%lld, pproject is NULL!", project_req_id, project_req_value);
		return -1;
	}

	pinfo[project_req_id].value = project_req_value;
	if(0 == pinfo[project_req_id].valid_flag){
		sapp_global_val->mthread_volatile[stream->threadnum]->sys_stat.count_project_in_use[project_req_id]++;
	}
	pinfo[project_req_id].valid_flag = 1;
	
	return 0;	
}

int project_req_add_char(struct streaminfo *stream, int project_req_id, char project_req_value)
{
	return __project_req_add(stream, project_req_id, (long long)project_req_value, PROGECT_REQ_VALUE_TYPE_SIMPLE_CHAR);
}

int project_req_add_uchar(struct streaminfo *stream, int project_req_id, unsigned char project_req_value)
{
	return __project_req_add(stream, project_req_id, (long long)project_req_value, PROGECT_REQ_VALUE_TYPE_SIMPLE_CHAR);
}

int project_req_add_short(struct streaminfo *stream, int project_req_id, short project_req_value)
{
	return __project_req_add(stream, project_req_id, (long long)project_req_value, PROGECT_REQ_VALUE_TYPE_SIMPLE_SHORT);
}

int project_req_add_ushort(struct streaminfo *stream, int project_req_id, unsigned short project_req_value)
{
	return __project_req_add(stream, project_req_id, (long long)project_req_value, PROGECT_REQ_VALUE_TYPE_SIMPLE_SHORT);
}

int project_req_add_int(struct streaminfo *stream, int project_req_id, int project_req_value)
{
	return __project_req_add(stream, project_req_id, (long long)project_req_value, PROGECT_REQ_VALUE_TYPE_SIMPLE_INT);
}

int project_req_add_uint(struct streaminfo *stream, int project_req_id, unsigned int project_req_value)
{
	return __project_req_add(stream, project_req_id, (long long)project_req_value, PROGECT_REQ_VALUE_TYPE_SIMPLE_INT);
}

int project_req_add_long(struct streaminfo *stream, int project_req_id, long project_req_value)
{
	return __project_req_add(stream, project_req_id, (long long)project_req_value, PROGECT_REQ_VALUE_TYPE_SIMPLE_LONG);
}

int project_req_add_ulong(struct streaminfo *stream, int project_req_id, unsigned long project_req_value)
{
	return __project_req_add(stream, project_req_id, (long long)project_req_value, PROGECT_REQ_VALUE_TYPE_SIMPLE_LONG);
}

int project_req_add_struct(struct streaminfo *stream, int project_req_id, const void *project_req_value)
{
	return __project_req_add(stream, project_req_id, (long long)project_req_value, PROGECT_REQ_VALUE_TYPE_STRUCT);
}

static long long __project_req_get(const struct streaminfo *stream, int project_req_id)
{
	project_req_info_t *pinfo;
	long long value = -1;
	struct streaminfo_private *stream_pr;
	
	if(project_req_id < 0 || project_req_id >= G_PROJECT_PLUG_NUM){
		errno = ERANGE;
		return -1;
	}

	stream_pr = (struct streaminfo_private *)stream;	
	if(NULL == stream_pr->pproject){
		errno = ERANGE;
		return  -1;
	}

	pinfo = (project_req_info_t *)(stream_pr->pproject);

	if(NULL == pinfo){
		sapp_runtime_log(RLOG_LV_FATAL, "project get error, id=%d, pproject is NULL!", project_req_id);
		return -1;
	}

	if(0 == pinfo[project_req_id].valid_flag){ /* 生产者还未设置过, 返回-1并设置errno */
		errno = ERANGE;
		return  -1;
	}
	value = pinfo[project_req_id].value;
	errno = 0;

	return value;
}


char project_req_get_char(const struct streaminfo *stream, int project_req_id)
{
	return (char )__project_req_get(stream, project_req_id);
}

unsigned char project_req_get_uchar(const struct streaminfo *stream, int project_req_id)
{
	return (unsigned char )__project_req_get(stream, project_req_id);
}

short project_req_get_short(const struct streaminfo *stream, int project_req_id)
{
	return (short )__project_req_get(stream, project_req_id);
}

unsigned short project_req_get_ushort(const struct streaminfo *stream, int project_req_id)
{
	return (unsigned short )__project_req_get(stream, project_req_id);
}

int project_req_get_int(const struct streaminfo *stream, int project_req_id)
{
	return (int )__project_req_get(stream, project_req_id);
}

unsigned int project_req_get_uint(const struct streaminfo *stream, int project_req_id)
{
	return (unsigned int )__project_req_get(stream, project_req_id);
}

long project_req_get_long(const struct streaminfo *stream, int project_req_id)
{
	return (long )__project_req_get(stream, project_req_id);
}

unsigned long project_req_get_ulong(const struct streaminfo *stream, int project_req_id)
{
	return (unsigned long )__project_req_get(stream, project_req_id);
}

const void *project_req_get_struct(const struct streaminfo *stream, int project_req_id)
{
	long long ret;

	ret = __project_req_get(stream, project_req_id);
	if(-1 == ret){
		return (const void *)0;
	}
	
	return (const void *)ret;
}


void project_requirement_destroy(int mem_use_type, int thread_num, void *pproject)
{
	int i;
	project_req_info_t *pinfo;
	
	if(NULL == pproject){
		return;
	}

	pinfo = (project_req_info_t *)(pproject);

	for(i = 0; i < 	G_PROJECT_PLUG_NUM; i++){
		if(pinfo[i].valid_flag != 0){
			sapp_global_val->mthread_volatile[thread_num]->sys_stat.count_project_in_use[i]--;			
		}
		if(PROGECT_REQ_VALUE_TYPE_STRUCT == G_PROJECT_REQ_MANAGE[i].project_req_type){
			if(pinfo[i].value != 0){
				if(G_PROJECT_REQ_MANAGE[i].free_cb != NULL){
					(*(G_PROJECT_REQ_MANAGE[i].free_cb))(thread_num, (void *)pinfo[i].value); /* 插件自己申请的内存无法统计  */
				}
				pinfo[i].value = 0;
			}
		}else{
			pinfo[i].value = -1;
		}
		pinfo[i].valid_flag = 0;
	}

	sapp_mem_free((sapp_mem_type_t)mem_use_type, thread_num, pproject);

	return;
}

/* 新建一个流结构时调用 */
void *project_requirement_create(int mem_use_type, int thread_num)
{
	project_req_info_t *pinfo;

	if(0 == G_PROJECT_PLUG_NUM){
		return NULL;
	}

	pinfo = (project_req_info_t *)sapp_mem_malloc((sapp_mem_type_t)mem_use_type,thread_num, sizeof(project_req_info_t) * G_PROJECT_PLUG_NUM);
	memset(pinfo, 0, sizeof(project_req_info_t) * G_PROJECT_PLUG_NUM);

	return (void *)pinfo;
}




/* 
	2015-12-25 lijia add, for TCP/UDP流量统计, 平台内置功能,
	因为UDP需要累计包数, 在ONE_STATE, TWO_STATE链表迁移, 固定开启.
*/
extern int G_UDP_TEREDO_IDENTIFY_PROJECT_ID ;

static int teredo_identify_init(void)
{
	G_UDP_TEREDO_IDENTIFY_PROJECT_ID = project_platform_register("__tunnel_teredo_identify", 
							PROGECT_REQ_VALUE_TYPE_SIMPLE_LONG, NULL);

	return G_UDP_TEREDO_IDENTIFY_PROJECT_ID;
}


static void terminal_tag_free_struct(int thread_num, void *project_req_value)
{
	dictator_free(thread_num, project_req_value);
}

int project_req_terminal_tag_id = -1;

int project_req_terminal_tag_init(void)
{
	int project_req_id;
	
	project_req_id = project_producer_register("terminal_tag", "struct", terminal_tag_free_struct);
	if(project_req_id >= 0){
		project_req_terminal_tag_id = project_req_id;
	}else{
		/* 配置文件没有'terminal_tag'项, 关闭此功能 */
		project_req_terminal_tag_id = -1;
	}
	
	return 0;
}

static void udp_flow_stat_free(int thread_seq, void *project_req_value)
{
	sapp_mem_free(SAPP_MEM_DYN_UDP_FLOW_STAT, thread_seq, project_req_value);

	return;
}

/* 
	2015-12-25 lijia add, for TCP/UDP流量统计, 平台内置功能,
	因为UDP需要累计包数, 在ONE_STATE, TWO_STATE链表迁移.
*/
static int udp_flow_stat_init(void)
{
	int temp_id;
	temp_id = project_producer_register(PROJECT_REQ_UDP_FLOW,  "struct", udp_flow_stat_free);

	if(temp_id >= 0){
		G_UDP_FLOW_STAT_PROJECT_ID = temp_id;			
	}else{
		/* 配置文件没有'tcp_flow_stat'项, 关闭此功能 */
		G_UDP_FLOW_STAT_PROJECT_ID = -1;
	}

	return 0;
}

static void project_env_init()
{
	int i;
	MESA_htable_create_args_t hargs;
	
	memset(&hargs, 0, sizeof(MESA_htable_create_args_t));
	hargs.thread_safe = 0;
	hargs.hash_slot_size = PROJECT_REQ_MAX_PLUG_NUM;
	hargs.max_elem_num = 0;
	hargs.eliminate_type = HASH_ELIMINATE_ALGO_FIFO;
	hargs.expire_time = 0;
	hargs.key_comp = NULL;
	hargs.key2index = NULL;
	hargs.data_free = free;
	hargs.data_expire_with_condition = NULL;
	hargs.recursive = 1;

	if(G_PROJECT_NAME_HASH == NULL)
	{
		G_PROJECT_NAME_HASH	= MESA_htable_create(&hargs, sizeof(hargs));
		if(G_PROJECT_NAME_HASH == NULL)
		{
			MESA_htable_destroy(G_PROJECT_NAME_HASH, NULL);
		}
	}
	
	return;
}

int project_requirement_global_init(void)
{
	project_env_init();
	/* 平台内部固定开启的模块初始化 */
	teredo_identify_init();

	//parse_project_req_conf();
	
	/* 平台内置project模块初始化, 功能是否启用取决于配置文件开关 */
	//project_req_terminal_tag_init();

	/* project注册改为动态, 不靠project_list.conf控制了,
	   但是下面这些内置功能为了向前兼容,还是检查一下project_list.conf是否存在, 不存在则不开启 */
	if(project_req_conf_is_exist(RAW_FRAG_V4_MODULE_NAME)){   
		raw_ip_frag_list_v4_init();
	}
	if(project_req_conf_is_exist(RAW_FRAG_V6_MODULE_NAME)){   
		raw_ip_frag_list_v6_init();
	}
	
	tcp_flow_stat_init();
	udp_flow_stat_init();

	return 0;
}


void global_project_req_destroy(void)
{
	raw_ip_frag_list_v4_destroy();
	raw_ip_frag_list_v6_destroy();

	MESA_htable_destroy(G_PROJECT_NAME_HASH, NULL);
	G_PROJECT_NAME_HASH = NULL;

	G_PROJECT_PLUG_NUM = 0;
	memset(G_PROJECT_REQ_MANAGE, 0, sizeof(G_PROJECT_REQ_MANAGE));
}

#ifdef __cplusplus
}
#endif

