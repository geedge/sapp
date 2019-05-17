#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"

extern int g_packet_io_thread_num;
extern int project_req_terminal_tag_init(void);
extern int raw_ip_frag_list_v4_init(void);
extern int raw_ip_frag_list_v6_init(void);
extern void del_last_rn(char *data, int max_len);
extern int tcp_flow_stat_init(void);
extern int G_UDP_FLOW_STAT_PROJECT_ID;

#define PROJECT_CONF_NAME				"conf/project_list.conf"
#define PROJECT_REQ_MAX_PLUG_NUM			(128)

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

static int G_PROJECT_PLUG_NUM = 0;

static struct pro_req_type G_PROJECT_TYPE[PROGECT_REQ_VALUE_TYPE_MAX] = 
{
	{PROGECT_REQ_VALUE_TYPE_SIMPLE_CHAR,	(char *)"char"},
	{PROGECT_REQ_VALUE_TYPE_SIMPLE_SHORT,	(char *)"short"},
	{PROGECT_REQ_VALUE_TYPE_SIMPLE_INT,		(char *)"int"},
	{PROGECT_REQ_VALUE_TYPE_SIMPLE_LONG,	(char *)"long"},
	{PROGECT_REQ_VALUE_TYPE_STRUCT,		(char *)"struct"},
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
		//printf("can't found project name:'%s' in %s\n", project_req_name, PROJECT_CONF_NAME);
		return -1;
	}

	return pro_req_id;
}

int project_producer_register(const char *project_req_name, const char *project_req_val_type, project_req_free_t *free_cb)
{
	int pro_req_id = -1;

	pro_req_id = __project_find_id_by_name(project_req_name, project_req_val_type);

	if(pro_req_id != -1){
		if((NULL == free_cb )
		&& (PROGECT_REQ_VALUE_TYPE_STRUCT == G_PROJECT_REQ_MANAGE[pro_req_id].project_req_type)){
			printf("project_producer_register() must implement 'free_cb' with 'struct' type!\n");
			return -1;
		}
		G_PROJECT_REQ_MANAGE[pro_req_id].free_cb = free_cb;
	}
	
	return pro_req_id;
}

int project_customer_register(const char *project_req_name, const char *project_req_val_type)
{
	return __project_find_id_by_name(project_req_name, project_req_val_type);
}


int parse_project_req_conf(void)
{
	char *save_ptr;
	const char *delim = "\t ";
	char line_buf[1024];
	FILE *fp;
	char *preq_name;
	char *preq_type;
	int i, line_num = 1;
	

	fp = fopen(PROJECT_CONF_NAME, "r");
	if(NULL == fp){
		printf("Open '%s' error: %s\n ", PROJECT_CONF_NAME, strerror(errno));
		return -1;
	}

	while(fgets(line_buf, 1024, fp) != NULL){
		if('#' == line_buf[0] || ' ' == line_buf[0] || '\r' == line_buf[0] || '\n' == line_buf[0]){
			line_num++;
			continue;
		}
		del_last_rn(line_buf, 1024);
		
		preq_name = strtok_r(line_buf, delim, &save_ptr);
		if(NULL == preq_name){
			printf("invalid conf in %s, line %d\n", PROJECT_CONF_NAME, line_num);
			return -1;
		}

		preq_type = strtok_r(NULL, delim, &save_ptr);
		if(NULL == preq_type){
			printf("invalid conf in %s, line %d\n", PROJECT_CONF_NAME, line_num);
			return -1;
		}

		while(strtok_r(NULL, delim, &save_ptr));

		/* search duplicate conf */
		for(i = 0; i < G_PROJECT_PLUG_NUM; i++){
			if(strncasecmp(preq_name, G_PROJECT_REQ_MANAGE[i].project_req_name, PROJECT_REQ_NAME_MAX_LEN) == 0){
				printf("duplicate conf in %s, line %d\n", PROJECT_CONF_NAME, line_num);
				return -1;
			}
		}
	
		G_PROJECT_REQ_MANAGE[G_PROJECT_PLUG_NUM].project_req_id = G_PROJECT_PLUG_NUM;
		strncpy(G_PROJECT_REQ_MANAGE[G_PROJECT_PLUG_NUM].project_req_name, preq_name, PROJECT_REQ_NAME_MAX_LEN);
		G_PROJECT_REQ_MANAGE[G_PROJECT_PLUG_NUM].project_req_type = project_req_str_to_type_id(preq_type);
		if(G_PROJECT_REQ_MANAGE[G_PROJECT_PLUG_NUM].project_req_type < 0){
			printf("invalid conf in %s, line %d\n", PROJECT_CONF_NAME, line_num);
			return -1;
		}
	
		line_num++;
		G_PROJECT_PLUG_NUM++;
	}

	fclose(fp);
	return 0;
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

	pinfo[project_req_id].value = project_req_value;
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


void project_requirement_destroy(int thread_num, void *pproject)
{
	int i;
	project_req_info_t *pinfo;
	
	if(NULL == pproject){
		return;
	}

	pinfo = (project_req_info_t *)(pproject);

	for(i = 0; i < 	G_PROJECT_PLUG_NUM; i++){
		if(PROGECT_REQ_VALUE_TYPE_STRUCT == G_PROJECT_REQ_MANAGE[i].project_req_type){
			if(pinfo[i].value != 0){
				if(G_PROJECT_REQ_MANAGE[i].free_cb != NULL){
					(*(G_PROJECT_REQ_MANAGE[i].free_cb))(thread_num, (void *)pinfo[i].value);
				}
#if 0				
				else{
					/* 没有注册清理函数, 默认把内存直接释放 */
					dictator_free(thread_num, (void *)(pinfo[i].value));
				}
#endif				
				pinfo[i].value = 0;
			}
		}else{
			pinfo[i].value = -1;
		}
	}

	dictator_free(thread_num, pproject);

	return;
}

/* 新建一个流结构时调用 */
void *project_requirement_create(int thread_num)
{
	project_req_info_t *pinfo;

	if(0 == G_PROJECT_PLUG_NUM){
		return NULL;
	}

	pinfo = (project_req_info_t *)dictator_malloc(thread_num, sizeof(project_req_info_t) * G_PROJECT_PLUG_NUM);
	memset(pinfo, 0, sizeof(project_req_info_t) * G_PROJECT_PLUG_NUM);

	return (void *)pinfo;
}


static int project_platform_register(const char *project_req_name, enum pro_type_list type, project_req_free_t *free_cb)
{
	int pid = G_PROJECT_PLUG_NUM;
	
	G_PROJECT_REQ_MANAGE[G_PROJECT_PLUG_NUM].project_req_id = G_PROJECT_PLUG_NUM;
	strncpy(G_PROJECT_REQ_MANAGE[G_PROJECT_PLUG_NUM].project_req_name, project_req_name, PROJECT_REQ_NAME_MAX_LEN);
	G_PROJECT_REQ_MANAGE[G_PROJECT_PLUG_NUM].free_cb = free_cb;
	G_PROJECT_REQ_MANAGE[G_PROJECT_PLUG_NUM].project_req_type = type;

	G_PROJECT_PLUG_NUM++;

	return pid;
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

	return 0;
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
	dictator_free(thread_seq, project_req_value);

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

int project_requirement_global_init(void)
{
	/* 平台内部固定开启的模块初始化 */
	teredo_identify_init();

	parse_project_req_conf();
	
	/* 平台内置project模块初始化, 功能是否启用取决于配置文件开关 */
	project_req_terminal_tag_init();
	raw_ip_frag_list_v4_init();
	raw_ip_frag_list_v6_init();

	tcp_flow_stat_init();
	udp_flow_stat_init();

	return 0;
}

#ifdef __cplusplus
}
#endif

