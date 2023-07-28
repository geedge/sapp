/*
	2016-01-12 LiJia add,
		Linux链接器对于重名的全局符号名称, 无警告, 默认以第一个出现的为准,
		导致出现BUG后, 很难定位真实原因.
		
		检测多个库之间的全局符号名冲突, 避免因重命名导致的莫名其妙的BUG.
*/
#include "sapp_api.h"
#include "sapp_private_api.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SYMBOL_DEBUG					(0)
#define SYMBOL_MAX_LEN				(256)
#define SYMBOL_GLOBAL_WARNING_LEN	(6)

static MESA_htable_handle __SYMBOL_CHK_HTABLE = NULL;

/*
	readelf对于太长的符号名显示不全;
	nm, objdump目前还没发现有长度限制.
*/
#define SYMBOL_GET_TYPE		(2) /*  1:readelf; 2:objdump; 3:nm */

#if (1 == SYMBOL_GET_TYPE)
#define SYMBOL_GET_CMD		"readelf -s %s | grep GLOBAL | awk {'print $2\" \"$3\" \"$4\" \"$5\" \" $6\" \"$7\" \" $8'} | sort | uniq"
#elif (2 == SYMBOL_GET_TYPE)
#define SYMBOL_GET_CMD		"objdump -t %s | grep -v \"0000000000000000\" | awk {'print $2\" \"$6'}"
#else
#endif


typedef struct {
	int Size;
	int Type;
	int Bind;
	int Vis;
	int Ndx;
	char Name[SYMBOL_MAX_LEN]; /* 插入HASH时会malloc, 此处暂时使用栈空间 */
}so_symbol_info_t;

typedef struct{
	char *so_file_name;
	int so_file_name_len; /* plus EOF */
}so_file_info_t;

/* Linux系统内置库, 不检查这些 */
static const char *_G_SYSTEM_RESERVE_LIB[] = 
{
	"ld-linux-x86-64.so",
	"libc.so",
	"libc.so.6",
	"libdl.so",
	"libm.so",
	"libm.so.6",
	"libgcc_s.so",
	"libpthread.so",
	"librt.so",
	"libstdc++.so",
	"libstdc++.so.6",
	"linux-vdso.so",
	"libpcap.so",
	"libpag.so",
	"libpfring.so",
	"GBK.so",
	"UNICODE.so",
	"BIG5.so",
	NULL,
};

/* C语言内置关键字或开始函数, 不检查 */
static const char *_G_SYSTEM_RESERVE_FUN[] = 
{
	"main",
	NULL,
};


#if (1 == SYMBOL_GET_TYPE)
typedef enum{
	LOCAL		=	0,
	GLOBAL		=	1,
	WEAK		=	2,
	__BOTHER	=	3,
}symbol_bind_def_t;


typedef struct{
	symbol_bind_def_t bin_type;
	const char *str_type;
}symbol_bind_conv_t;


typedef enum{
	SECTION		=	0,
	FUNC		=	1,
	TFILE		=	2,
	OBJECT		=	3,
	NOTYPE		=	4,
	__TOTHER	=	5,
}symbol_type_def_t;


typedef struct{
	symbol_type_def_t bin_type;
	const char *str_type;
}symbol_type_conv_t;

typedef enum{
	DEFAULT	=	0,
	HIDDEN		=	1,
	__VOTHER	=	2,
}symbol_vis_def_t;

typedef struct{
	symbol_vis_def_t bin_type;
	const char *str_type;
}symbol_vis_conv_t;

typedef enum{
	UND			=	0,
	ABS			=	1,
	INTEGER		=	2, /* 数字 */
	__NOTHER	=	3,
}symbol_ndx_def_t;

typedef struct{
	symbol_ndx_def_t bin_type;
	const char *str_type;
}symbol_ndx_conv_t;


static symbol_type_conv_t __G_SYMBOL_TYPE_CONV[__TOTHER] = 
{
	{SECTION, 	"SECTION"},
	{FUNC,		"FUNC"},
	{TFILE,		"FILE"},
	{OBJECT,	"OBJECT"},
	{NOTYPE,	"NOTYPE"},
};


static symbol_bind_conv_t __G_SYMBOL_BIND_CONV[__BOTHER] = 
{	
	{LOCAL, 	"LOCAL"},
	{GLOBAL,	"GLOBAL"},
	{WEAK,		"WEAK"},
};


static symbol_vis_conv_t __G_SYMBOL_VIS_CONV[__VOTHER] = 
{	
	{DEFAULT, 	"DEFAULT"},
	{HIDDEN,	"HIDDEN"},
};

static symbol_ndx_conv_t __G_SYMBOL_NDX_CONV[__NOTHER] = 
{	
	{UND, 		"UND"},
	{ABS,		"ABS"},
	{INTEGER,	"INTEGER"},
};

#endif

/* 删除末尾的换行符"\r\n" */
static void _symbol_chk_del_last_rn(char *data, int max_len)
{
    int i;
    for(i = 0; i < max_len; i++){
        if(('\r' == data[i]) || ('\n' == data[i])){
            data[i] = '\0';
            return;
        }
    }

    return;
}

#if (1 == SYMBOL_GET_TYPE)
static int symbol_transform_type(const char *type)
{
	int i;

	for(i = 0; i < __TOTHER; i++){
		if(strncasecmp(__G_SYMBOL_TYPE_CONV[i].str_type, type, strlen(type)) == 0){
			return __G_SYMBOL_TYPE_CONV[i].bin_type;
		}
	}

	return __TOTHER;
}

static int symbol_transform_bind(const char *bind)
{
	int i;

	for(i = 0; i < __BOTHER; i++){
		if(strncasecmp(__G_SYMBOL_BIND_CONV[i].str_type, bind, strlen(bind)) == 0){
			return __G_SYMBOL_BIND_CONV[i].bin_type;
		}
	}

	return __BOTHER;
}

static int symbol_transform_vis(const char *vis)
{
	int i;

	for(i = 0; i < __VOTHER; i++){
		if(strncasecmp(__G_SYMBOL_VIS_CONV[i].str_type, vis, strlen(vis)) == 0){
			return __G_SYMBOL_VIS_CONV[i].bin_type;
		}
	}

	return __BOTHER;
}


static int symbol_transform_ndx(const char *ndx)
{
	int i;

	for(i = 0; i < __NOTHER; i++){
		if(strncasecmp(__G_SYMBOL_NDX_CONV[i].str_type, ndx, strlen(ndx)) == 0){
			return __G_SYMBOL_NDX_CONV[i].bin_type;
		}else if(isdigit(*ndx)){
			return INTEGER;
		}
	}

	return __BOTHER;
}
#endif

#if (1 == SYMBOL_GET_TYPE)
/*
	example:
	
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     2: 0000000000000000     0 NOTYPE  GLOBAL DEFAULT  UND pthread_mutex_trylock
     3: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND pthread_cond_destroy@GLIBC_2.3.2 (2)

*/
static int symbol_convert_by_readelf(char *symbol_str, so_symbol_info_t *symbol_bin_info)
{
	const char *delim = "\t ";
	char *saveptr = NULL;
	char *section;

	//section = strtok_r(symbol_str, delim, &saveptr); /* Num,  第一列用命令中的awk已经去除 */
	section = strtok_r(symbol_str, delim, &saveptr); /* Value, not need */
	if(NULL == section){
		goto err;
	}
	symbol_str = NULL;
	section = strtok_r(symbol_str, delim, &saveptr); /* Size */
	if(NULL == section){
		goto err;
	}
	if(atoi(section) == 0){
		goto err;
	}

	section = strtok_r(symbol_str, delim, &saveptr); /* Type */
	if(NULL == section){
		goto err;
	}
	symbol_bin_info->Type = symbol_transform_type(section);
	switch(symbol_bin_info->Type){
		case FUNC:
		case OBJECT:
		break;

		default:
			goto err; /* 未知类型, 无需再处理 */
	}


	section = strtok_r(symbol_str, delim, &saveptr); /* bind */
	if(NULL == section){
		goto err;
	}
	symbol_bin_info->Bind = symbol_transform_bind(section);
	if(GLOBAL != symbol_bin_info->Bind){
		goto err; /* 未知类型, 无需再处理 */
	}


	section = strtok_r(symbol_str, delim, &saveptr); /* Vis */
	if(NULL == section){
		goto err;
	}
	symbol_bin_info->Vis = symbol_transform_vis(section);
	if(DEFAULT != symbol_bin_info->Vis){
		goto err; /* 未知类型, 无需再处理 */
	}


	section = strtok_r(symbol_str, delim, &saveptr); /* Ndx */
	if(NULL == section){
		goto err;
	}
	symbol_bin_info->Ndx = symbol_transform_ndx(section);
	if(INTEGER != symbol_bin_info->Ndx){
		goto err; /* 未知类型, 无需再处理 */
	}

	section = strtok_r(symbol_str, delim, &saveptr); /* Name */
	if(NULL == section){
		goto err;
	}

	if(strlen(section)+1 >= SYMBOL_MAX_LEN){
		printf("too long symbol:%s\n", section);
		goto err;
	}

	_symbol_chk_del_last_rn(section, strlen(section) +1);

	memcpy(symbol_bin_info->Name, section, strlen(section)+1);
	
	while(strtok_r(symbol_str, delim, &saveptr));
	return 0;

err:	
	/* clear all static buf */
	while(strtok_r(symbol_str, delim, &saveptr));
	return -1;
}
#endif

#if (2 == SYMBOL_GET_TYPE)
/*
	过滤之后, 只剩两列: 
	l	symbol_a
	g	symbol_b
*/
static int symbol_convert_by_objdump(char *symbol_str, so_symbol_info_t *symbol_bin_info)
{
	const char *delim = "\t ";
	char *saveptr = NULL;
	char *section;

	section = strtok_r(symbol_str, delim, &saveptr); /* symbol type */
	if(NULL == section){
		goto err;
	}

	if('g' != *section){ /* 只检查global类型符号 */
		goto err;
	}

	section = strtok_r(NULL, delim, &saveptr); /* symbol_string */
	if(NULL == section){
		goto err;
	}
	_symbol_chk_del_last_rn(section, strlen(section) +1); 
	if(strlen(section) == 0){
		goto err;
	}
	
	memcpy(symbol_bin_info->Name, section, strlen(section)+1);
	
	while(strtok_r(NULL, delim, &saveptr));
	return 0;

err:	
	/* clear all static buf */
	while(strtok_r(NULL, delim, &saveptr));
	return -1;
}
#endif

static int symbol_insert_hash(so_file_info_t *so_file_info, so_symbol_info_t *so_symbol_info, int *user_arg)
{
	so_file_info_t *in_htable_so_info;
	int ret;

	in_htable_so_info = (so_file_info_t *)MESA_htable_search(__SYMBOL_CHK_HTABLE, 
													(const uchar *)so_symbol_info->Name, 
													strlen(so_symbol_info->Name)+1); 
	if(NULL == in_htable_so_info){
		ret = MESA_htable_add(__SYMBOL_CHK_HTABLE, 
							(const uchar *)so_symbol_info->Name, 
							strlen(so_symbol_info->Name)+1, 
							(const void *)so_file_info);
		assert(ret >= 0);
	}else{
		printf("\033[33m[Warning]Symbol conflict: \033[0m\n");
		printf("\033[33m\t In %s -> %s \033[0m\n", so_file_info->so_file_name, so_symbol_info->Name);
		printf("\033[33m\t In %s -> %s \033[0m\n", in_htable_so_info->so_file_name, so_symbol_info->Name);
		printf("\033[33m\t You should use 'readelf -s', 'objdump -t' or 'nm', check this problem!\033[0m\n");
		*user_arg = -1;
		ret = -1;
	}

	return ret;
}

static int symbol_file_check(const char *raw_filename, void *user_arg)
{
	char cmd_buf[PATH_MAX];
	char filename[PATH_MAX];
	char symbol_info_buf[PATH_MAX];
	FILE *fp;
	so_file_info_t *so_file_info; 
	so_symbol_info_t so_symbol_info;
	int i, ret;
	const char *file_base_name;
	int insert_hash_succ_num = 0;
	
	if((NULL == raw_filename) || ('\0' == raw_filename[0]) || ('\n' == raw_filename[0])){
		return -1;
	}

	strncpy(filename, raw_filename, PATH_MAX); /* copy一次, basename可能修改原始字符串 */
	file_base_name = (const char *)basename(filename);
	for(i = 0; _G_SYSTEM_RESERVE_LIB[i] != NULL; i++){
		if(strncasecmp(file_base_name, (const char *)_G_SYSTEM_RESERVE_LIB[i], strlen(_G_SYSTEM_RESERVE_LIB[i])) == 0){
			return -1; /* 系统标准函数库 */
		}
	}

	so_file_info = (so_file_info_t *)malloc(sizeof(so_file_info_t));
	memset(so_file_info, 0, sizeof(so_file_info_t));

	so_file_info->so_file_name_len = strlen(filename) + 1;
	so_file_info->so_file_name = (char *)malloc(so_file_info->so_file_name_len); /* add EOF */
	memcpy(so_file_info->so_file_name, filename, so_file_info->so_file_name_len);

	snprintf(cmd_buf, PATH_MAX, SYMBOL_GET_CMD, filename);
	
	fp = popen(cmd_buf, "r");	
	if(NULL == fp){
		printf("symbol_file_check() popen error, %s\n", strerror(errno));
		return 0;
	}
	while(fgets(symbol_info_buf, PATH_MAX, fp)){
#if (1 == SYMBOL_GET_TYPE)	
		ret = symbol_convert_by_readelf(symbol_info_buf, &so_symbol_info);
#elif (2 == SYMBOL_GET_TYPE)			
		ret = symbol_convert_by_objdump(symbol_info_buf, &so_symbol_info);
#else
		//TODO 1
#endif
		if(ret >= 0){
			ret = symbol_insert_hash(so_file_info, &so_symbol_info, (int *)user_arg);
			if(ret >= 0){
				insert_hash_succ_num++;
			}
		}
	}
	pclose(fp);
	if(0 == insert_hash_succ_num){
		free(so_file_info->so_file_name);
		free(so_file_info);
	}
	
	return 0;	
}


static int dl_iterate_callback(struct dl_phdr_info *info, size_t size, void *user_arg)
{
	if((NULL == info->dlpi_name) || ('\0' == info->dlpi_name[0])){
		return 0;
	}

#if SYMBOL_DEBUG
	printf("so_file_name: %s\n", info->dlpi_name);
#endif

	symbol_file_check(info->dlpi_name, user_arg);

	return 0;
}


static int symbol_key_cmp(const uchar * key1, uint size1, const uchar * key2, uint size2)
{
	if(size1 != size2){
		return -1;
	}

	if(strncasecmp((const char *)key1, (const char *)key2, size1) != 0){
		return -1;
	}

	return 0;
}

static void *symbol_htable_create(void)
{
	MESA_htable_create_args_t hargs;

	memset(&hargs, 0, sizeof(MESA_htable_create_args_t));

	hargs.thread_safe = 1;
	hargs.recursive = 1;
	hargs.hash_slot_size = 1024 * 1024;
	hargs.max_elem_num = 0;
	hargs.eliminate_type = HASH_ELIMINATE_ALGO_LRU;
	hargs.expire_time = 0;
	hargs.key_comp = symbol_key_cmp;
	hargs.key2index = NULL;
	hargs.data_free = NULL;
	hargs.data_expire_with_condition = NULL;

	return MESA_htable_create(&hargs, sizeof(MESA_htable_create_args_t));
}

static void symbol_foresight_check_cb(const uchar * key, uint size, void * data, void *user)
{
	int i;
	so_file_info_t *so_file_info = (so_file_info_t *)data;
	
	if(size <= SYMBOL_GLOBAL_WARNING_LEN){
		for(i = 0; _G_SYSTEM_RESERVE_FUN[i] != NULL; i++){
			if(strncasecmp((const char *)key, (const char *)_G_SYSTEM_RESERVE_FUN[i], strlen(_G_SYSTEM_RESERVE_FUN[i])) == 0){
				return; /* 系统标准函数库 */
			}
		}	
		printf("\033[33m[Warning]in %s, global symbol '%s' is too short.\033[0m\n", so_file_info->so_file_name, key);
	}
}

/* 全局变量global级别, 名称太短的打印警告信息 */
static void symbol_foresight_check(void)
{
	return; /* 全局变量名短, 但只要不冲突那暂时还是不打印了! */
	//MESA_htable_iterate(__SYMBOL_CHK_HTABLE, symbol_foresight_check_cb, NULL);
}

/*
	return value:
		0 :success;
		-1:symbol conflict;
*/


int symbol_check(void)
{
	int ret = 0;
	char exe_file_name[PATH_MAX];
	
	if(NULL == __SYMBOL_CHK_HTABLE){
		__SYMBOL_CHK_HTABLE = symbol_htable_create();
		MESA_htable_print_crtl(__SYMBOL_CHK_HTABLE, 0);
	}
	
	dl_iterate_phdr(dl_iterate_callback, &ret);

	memset(exe_file_name, 0, PATH_MAX);
	readlink("/proc/self/exe", exe_file_name, PATH_MAX);
	symbol_file_check(exe_file_name, &ret);

	symbol_foresight_check();

	return ret;
}

void symbol_exit(void)
{
	MESA_htable_destroy(__SYMBOL_CHK_HTABLE, NULL);
}

#ifdef __cplusplus
}
#endif



